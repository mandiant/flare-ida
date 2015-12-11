#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2014 FireEye
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
########################################################################
# Traverse a directory, trying to find all exports for all valid PE
# executable files. Computes common shellcode hashes and stores them
# to a sqlite database file for later use, such as in IDA Pro.

import os
import sys
import time
import zlib
import ctypes
import os.path
import sqlite3

try:
    import pefile
except ImportError, err:
    print "Error while importing pefile module: %s" % str(err)
    print "Please make sure it is installed: http://code.google.com/p/pefile/"
    sys.exit(1)

#This is a list of interesting dll's to use if not traversing a directory
INTERESTING_DLLS = [
    'kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
    'gdi32.dll',    'msvcrt.dll',   'netapi32.dll', 'ntdll.dll',
    'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll',    'shell32.dll',
    'shlwapi.dll',  'srsvc.dll',    'urlmon.dll',   'user32.dll',
    'winhttp.dll',  'wininet.dll',  'ws2_32.dll',   'wship6.dll',
    'advpack.dll',
]

VERBOSE=False

############################################################
# SQL queries
############################################################
sql_testTableExists='''
SELECT name 
FROM sqlite_master 
WHERE name=?;
'''

sql_create_tables='''
create table symbol_hashes (
    hash_key        integer primary key,
    hash_val        integer,
    hash_type       integer,
    lib_key         integer,
    symbol_name     varchar(256)
);

create table source_libs (
    lib_key         integer primary key,
    lib_name        varchar(256)
);

create table hash_types (
    hash_type       integer primary key,
    hash_size       integer,
    hash_name       varchar(256),
    hash_code       text
);

--Index just the hash vals for when we don't know the hash type
create index idx_hash_val on symbol_hashes (hash_val);

--Index with hash_type prefix for when we know the type we're
-- looking for
create index idx_hash_type_hash_val on symbol_hashes (hash_type, hash_val);
'''

sql_add_hash_type='''
insert into hash_types ( 
    hash_size,
    hash_name,
    hash_code
) values (?,?,?);
'''

sql_get_hash_type='''
select 
    hash_type
from hash_types
where hash_name=?;
'''

sql_get_hash_type_hash_size='''
select 
    hash_type
from hash_types
where hash_name=? and hash_size=?;
'''

sql_add_source_lib='''
insert into source_libs (
    lib_name
) values (?);
'''

sql_add_symbol_hash='''
insert into symbol_hashes (
    hash_val, 
    hash_type, 
    lib_key, 
    symbol_name
) values (?,?,?,?);
'''

sql_lookup_hash_value='''
select 
    hash_key,
    hash_val,
    hash_type,
    source_lib,
    symbol_name
from symbol_hashes
where hash_val=?;
'''

sql_lookup_hash_value_hash_type='''
select 
    hash_key,
    hash_val,
    hash_type,
    source_lib,
    symbol_name
from symbol_hashes
where hash_val=? and hash_type=?;
'''

sql_find_source_lib_by_name='''
select
    lib_key
from source_libs
where lib_name=?;
'''

sql_find_symbol_hash_type_lib_symbol='''
select 
    hash_key
from symbol_hashes
where hash_val=? and hash_type=? and lib_key=? and symbol_name=?;
'''

############################################################
# Start of functions to implement operator primitives
############################################################

ROTATE_BITMASK = {
    8  : 0xff,
    16 : 0xffff,
    32 : 0xffffffff,
    64 : 0xffffffffffffffff,
}

def rcr(inVal, numShifts, cb, dataSize=32):
    '''rotate carry right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    #make sure carry in bit is only 0 or 1
    cb = cb & 1
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    #or the carry value in there
    bitMask = ROTATE_BITMASK[dataSize]
    inVal = inVal | (cb << dataSize)
    x = (dataSize - numShifts) + 1
    res = (inVal >> numShifts) | (inVal << x)
    return (bitMask & res, 1 & (res >> dataSize))

def ror(inVal, numShifts, dataSize=32):
    '''rotate right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    return bitMask & ((inVal >> numShifts) | (inVal << (dataSize-numShifts)))

def rol(inVal, numShifts, dataSize=32):
    '''rotate left instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    currVal = inVal
    return bitMask & ((inVal << numShifts) | (inVal >> (dataSize-numShifts)))

############################################################
# Start of hash implementations
############################################################

def poisonIvyHash(inStr,fName):
    #need a null at the end of the string
    if inStr[-1] != '\x00':
        inStr = inStr + '\x00'
    cx = 0xffff
    dx = 0xffff
    for b1 in inStr:
        bx = 0
        ax = ord(b1) ^ (cx & 0xff)
        cx =  ((cx>>8)&0xff) | ((dx&0xff)<<8)
        dx = ((dx>>8)&0xff) | 0x800
        while (dx & 0xff00) != 0:
            c_in = bx & 1
            bx = bx >> 1          
            ax, c_out = rcr(ax, 1, c_in, 16)
            if c_out != 0:
                ax = ax ^ 0x8320
                bx = bx ^ 0xedb8
            dx =  (dx&0xff) | (((((dx>>8)&0xff)-1)&0xff)<<8)
        cx = cx ^ ax
        dx = dx ^ bx
    dx = 0xffff & ~dx
    cx = 0xffff & ~cx
    return  0xffffffff & ((dx<<16) | cx)

pseudocode_poisonIvyHash = '''Too hard to explain.\nString hash function from POISON IVY RAT.\nSee code for information'''


def rol3XorEax(inString,fName):
    if inString is None:
        return 0
    ecx = 0
    eax = 0
    for i in inString:
        eax = eax | ord(i)
        ecx = ecx ^ eax
        ecx = rol(ecx, 0x3, 32)
        ecx += 1
        eax = 0xffffffff & (eax << 8)
    return ecx

pseudocode_rol3XorEax = '''eax := 0;
ecx := 0;
for c in input_string {
    eax := eax | c ;
    ecx := ecx ^ eax;
    ecx := ROL(ecx, 0x3);
    ecx : ecx + 1;
    eax := 0xffffffff & (eax << 8);
};
return ecx;
'''

def rol7AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val += ord(i)
    return val

pseudocode_rol7AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc + c;
}
'''

def rol5AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x5, 32)
        val += ord(i)
    return val

pseudocode_rol5AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 5):
   acc := acc + c;
}
'''



def ror7AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0x7, 32)
        val += ord(i)
    return val

pseudocode_ror7AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 7):
   acc := acc + c;
}
'''

def ror9AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0x9, 32)
        val += ord(i)
    return val

pseudocode_ror9AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 9);
   acc := acc + c;
}
'''

def ror11AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xb, 32)
        val += ord(i)
    return val

pseudocode_ror11AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 11);
   acc := acc + c;
}
'''

def ror13AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
    return val

pseudocode_ror13AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
'''

def ror13AddWithNullHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString + "\x00":
        val = ror(val, 0xd, 32)
        val += ord(i)
    return val

pseudocode_ror13AddWithNullHash32 = '''acc := 0;
for c in input_string_with_trailing_NULL {
   acc := ROR(acc, 13);
   acc := acc + c;
}
'''

def ror13AddHash32Sub1(inString,fName):
    '''Same as ror13AddHash32, but subtract 1 afterwards'''
    return ror13AddHash32(inString,fName) - 1

pseudocode_ror13AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
acc := acc - 1;
'''

def shl7shr19Hash32(inString,fName):
    val = 0
    for i in inString:
        edx = 0xffffffff & (val << 7)
        ecx = 0xffffffff & (val >> 0x19)
        eax = edx | ecx
        t = 0xff & (ord(i) ^ 0xf4)
        val = eax ^ t
    return val

pseudocode_shl7shr19Hash32 = '''acc := 0;
for c in input_string {
   t0 = (acc << 7);
   t1 = (acc >> 0x19);
   t2 = t0 | t1;
   acc = t2 ^ c ^ 0xf4;
}
'''

def sll1AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        b = ord(i)
        b = 0xff & (b | 0x60)
        val = val + b
        val = val << 1
        val = 0xffffffff & val
    return val

pseudocode_sll1AddHash32 = '''acc := 0;
for c in input_string {
    acc = acc + (c | 0x60);
    acc = acc << 1;
}
'''

def playWith0xedb88320Hash(inString,fName):
    esi = 0xFFFFFFFF
    for d in inString:
        c = ord(d)
        for i in range(8):
            eax = c
            eax ^= esi
            b0  = eax & 0xFF
            b0 &= 0x01
            b0  = -b0
            if b0 % 2 == 0: # sbb eax, eax
                eax = 0
            else:
                eax = 0xFFFFFFFF
            eax &= 0xedb88320
            esi >>= 1
            esi ^= eax
            c >>= 1
    return esi ^ 0xFFFFFFFF

pseudocode_playWith0xedb88320Hash = \
'''Too hard to explain, AND's with 0xedb88320, though.
String hash function from Gatak sample.
See code for information'''


def crc32(inString,fName):
    return 0xffffffff & (zlib.crc32(inString))

def ror13AddHash32AddDll(inString,fName):
    dllHash = 0
    for c in fName:
        dllHash = ror(dllHash, 0xd, 32)
        if ord(c) < 97:
            dllHash = int(dllHash) + ord(c)
        else:
            dllHash = int(dllHash) + ord(c) - 32
        dllHash = ror(dllHash, 0xd, 32)
    dllHash = ror(dllHash, 0xd, 32)
    dllHash = ror(dllHash, 0xd, 32)

    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
    val = ror(val, 0xd, 32)
    val += dllHash
    if val >= 4294967296:
        val -= 4294967296
    return val

pseudocode_ror13AddHash32AddDll = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
acc := acc + ror13add(DllName);
'''

def mult21AddHash32(inString,fName):
    acc = 0
    for i in inString:
        acc = 0xffffffff & (acc * 0x21)
        acc = 0xffffffff & (acc + ord(i))
    return acc


pseudocode_hashMult21 = '''acc := 0;
for c in input_string {
   acc := acc * 0x21;
   acc := acc + c;
}
'''

def add1505Shl5Hash32(inString,fName):
  val = 0x1505
  for ch in inString:
    val += (val << 5)
    val &= 0xFFFFFFFF
    val += ord(ch)
    val &= 0xFFFFFFFF
  return val

pseudocode_add1505Shl5Hash32 = '''val := 0x1505;
for c in input_string {
   val := val +  (val << 5);
   val := val + c;
}
'''

def rol7XorHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val = val ^ (0xff & ord(i))
    return val

pseudocode_rol7XorHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc ^ c;
}
'''

def rol7AddXor2Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val += (ord(i) ^ 2)
    return val

pseudocode_rol7AddXor2Hash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc + (c ^ 2);
}
'''





# The list of tuples of (supported hash name, hash size, pseudo_code)
HASH_TYPES = [
    ('ror13AddHash32',          32, pseudocode_ror13AddHash32),
    ('ror13AddWithNullHash32',  32, pseudocode_ror13AddWithNullHash32),
    ('ror13AddHash32AddDll',    32, pseudocode_ror13AddHash32AddDll),
    ('poisonIvyHash',           32, pseudocode_poisonIvyHash),
    ('rol7AddHash32',           32, pseudocode_rol7AddHash32),
    ('rol5AddHash32',           32, pseudocode_rol5AddHash32),
    ('rol3XorEax',              32, pseudocode_rol3XorEax),
    ('ror7AddHash32',           32, pseudocode_ror7AddHash32),
    ('ror9AddHash32',           32, pseudocode_ror9AddHash32),
    ('ror11AddHash32',          32, pseudocode_ror11AddHash32),
    ('ror13AddHash32Sub1',      32, pseudocode_ror13AddHash32),
    ('shl7shr19Hash32',         32, pseudocode_shl7shr19Hash32),
    ('sll1AddHash32',           32, pseudocode_sll1AddHash32),
    ('playWith0xedb88320Hash',  32, pseudocode_playWith0xedb88320Hash),
    ('crc32',                   32, 'Standard crc32'),
    ('mult21AddHash32',         32, pseudocode_hashMult21),
    ('add1505Shl5Hash32',       32, pseudocode_add1505Shl5Hash32),
    ('rol7XorHash32',           32, pseudocode_rol7XorHash32),
    ('rol7AddXor2Hash32',       32, pseudocode_rol7AddXor2Hash32),
]


############################################################
# Database creator
############################################################

class ShellcodeDbCreator(object):
    def __init__(self, dbPath, dirName):
        self.dbPath = dbPath
        self.dirName = dirName
        self.conn = sqlite3.connect(dbPath)
        self.initDb() 
        self.initHashesDict()

    def close(self):
        self.conn.close()
        self.conn = None

    def run(self):
        #process all the files in the given directory
        self.processDir(self.dirName)

    def initDb(self):
        #check for tables, create if not present
        if not self.checkForTable('symbol_hashes'):
            cur = self.conn.executescript(sql_create_tables)
            self.conn.commit()
        #add the known hashtypes
        for hashName, hashSize, hashCode in HASH_TYPES:
            self.addHashType(hashName, hashSize, hashCode)

    def initHashesDict(self):
        #The hashes dict will store tuple (hashtype_key, dyn method), 
        # indexed by name. used to iterate over when processing export names.
        self.hashes = {}
        for hashName, hashSize, hashCode in HASH_TYPES:
            try:
                meth = globals()[hashName]
                hashType = self.getHashTypeByName(hashName)
                self.hashes[hashName] = (hashType, meth)
            except AttributeError, err:
                print "Could not find method %s" % hashName
            
    def processDir(self, dirName):
        for fName in os.listdir(dirName):
            filePath = os.path.join(dirName, fName)
            if not os.path.isfile(filePath):
                #print "Could not find file: %s. Skipping" % fName
                continue
            try:
                peFile = pefile.PE(filePath)
                if ((not hasattr(peFile, "DIRECTORY_ENTRY_EXPORT")) or (peFile.DIRECTORY_ENTRY_EXPORT is None)):
                    if VERBOSE:
                        print "No exports: %s" % filePath
                else:
                    #add the library to the lib table
                    print "Processing file %s" % filePath
                    time1 = time.time()
                    libKey = self.addSourceLib(fName)
                    symCount = 0
                    for sym in peFile.DIRECTORY_ENTRY_EXPORT.symbols:
                        if sym.name is not None:
                            symCount += 1
                            for hashName in self.hashes.keys():
                                hashType, hashMeth = self.hashes[hashName]
                                #print "Trying to hash: %s:%s" % (hashName, sym.name)
                                symHash = hashMeth(sym.name,fName)
                                #print " Done hashing: %08x:%s" % (symHash, sym.name)
                                if symHash is not None:
                                    self.addSymbolHash(symHash, hashType, libKey, sym.name)
                    #commit outstanding transaction
                    self.conn.commit()
                    time2 = time.time()
                    timeDiff = time2 - time1
                    print "Processed %d export symbols in %.02f seconds: %s" % (symCount, timeDiff, filePath)

            except pefile.PEFormatError, err:
                if VERBOSE:
                    print "Skipping non-PE file %s: %s" % (filePath, str(err))
            except Exception, err:
                if VERBOSE:
                    print "Skipping %s: %s" % (filePath, str(err))
                raise

    def addHashType(self, hashName, hashSize, code):
        #check if the hashname already exists
        cur = self.conn.execute(sql_get_hash_type_hash_size, (hashName, hashSize))
        retList = cur.fetchall()
        if len(retList) > 0:
            return
        cur = self.conn.execute(sql_add_hash_type, (hashSize, hashName, code))
        self.conn.commit()
        if cur is None:
            raise RuntimeError("Cursor is None following hash type insert")
        if cur.lastrowid is None:
            raise RuntimeError("lastrowid is None following hash type insert")
        return cur.lastrowid

    def getHashTypeByName(self, hashName):
        '''
        Returns None if the hashName is not found, else returns
        the integer hash type key for the requested hash
        '''
        cur = self.conn.execute(sql_get_hash_type, (hashName, ))
        retList = cur.fetchall()
        if len(retList) == 0:
            return None
        elif len(retList) > 1:
            print "ERROR: database in odd state. Multiple entries for hash name: %s" % hashName
        #always return first entry, even on error
        return retList[0][0]

    def getSourceLibByName(self, libName):
        '''
        Returns None if the libName is not found, else returns
        the integer key for the requested souce lib.
        '''
        cur = self.conn.execute(sql_find_source_lib_by_name, (libName, ))
        retList = cur.fetchall()
        if len(retList) == 0:
            return None
        elif len(retList) > 1:
            print "ERROR: database in odd state. Multiple entries for source lib: %s" % libName
        #always return first entry, even on error
        return retList[0][0]

    def addSourceLib(self, libName):
        '''
        Adds the given source lib to the db (if not already present) & returns the lib key.
        '''
        #lookup the library, insert if it doesn't exist
        libKey = self.getSourceLibByName(libName)
        if libKey is None:
            cur = self.conn.execute(sql_add_source_lib, (libName, ))    
            self.conn.commit()
            if cur is None:
                raise RuntimeError("Cursor is None following source lib insert")
            if cur.lastrowid is None:
                raise RuntimeError("lastrowid is None following source lib insert")
            return cur.lastrowid
        else:
            return libKey

    def addSymbolHash(self, hashVal, hashType, libKey, symbolName):
        '''Note: requires explicit commit afterwards by caller'''
        #determine if tuple (hashVal, hashType, libKey, symbolName) already exists or not
        #print "Trying to add symbol: %s %s, %s %s, %s %s, %s %s" % (
        #    type(hashVal), str(hashVal), 
        #    type(hashType), str(hashType),
        #    type(libKey), str(libKey),
        #    type(symbolName), str(symbolName))
        cur = self.conn.execute(sql_find_symbol_hash_type_lib_symbol, 
            (hashVal, hashType, libKey, symbolName)
        )
        retList = cur.fetchall()
        if len(retList) == 0:
            #insert it now
            cur = self.conn.execute(sql_add_symbol_hash, 
                (hashVal, hashType, libKey, symbolName)
            )
            if cur is None:
                raise RuntimeError("Cursor is None following symbol hash insert")
            if cur.lastrowid is None:
                raise RuntimeError("lastrowid is None following symbol hash insert")
            return cur.lastrowid
        else:
            #print "Skipping duplicate hash: %08x %08x %08x %s" % (hashVal, hashType, libKey, symbolName)
            pass

    def checkForTable(self, tableName):
        '''
        Returns True if the given table name already exists, else returns False.
        '''
        cur = self.conn.execute(sql_testTableExists, (tableName,))
        row = cur.fetchone()
        if row is None:
            #raise UnpreparedDatabaseException("Missing database table: %s" % tableName)
            return False
        return True

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print "python %s <db_path> <dll_dir>" % sys.argv[0]
        sys.exit(1)
    dbPath = sys.argv[1]
    walkPath = sys.argv[2]
    hasher = ShellcodeDbCreator(dbPath, walkPath)
    hasher.run()
    hasher.close()
    print "Done with symbol name hashing"

