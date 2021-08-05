#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2014,2018 FireEye
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
########################################################################
#
# Searches in an IDB for known symbol hashes retrieved from a pre-calculated
# set stored in a sqlite db.
#
########################################################################

import sys
import ctypes
import logging
import os.path
import sqlite3

import idc
import idaapi
import idautils

from . import jayutils

QT_AVAILABLE = True
try:
    from PyQt5 import QtWidgets, QtCore
    from .shellcode_widget import ShellcodeWidget
except ImportError as err:
    print('ImportError: %s' % err)
    print ('Falling back to simple dialog-based GUI. \nPlease consider installing the HexRays PyQt5 build available at \n"http://hex-rays.com/products/ida/support/download.shtml"')
    QT_AVAILABLE = False


# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (ida_major > 6)

#logger = jayutils.configLogger('shellcode_hash', logging.DEBUG)
logger = jayutils.configLogger('shellcode_hash', logging.INFO)

class RejectionException(Exception):
    pass

if using_ida7api:
    import ida_ua
    OPERAND_MASK = {
        ida_ua.dt_byte:                0xFF,  # 1 byte
        ida_ua.dt_word:              0xFFFF,  # 2 bytes
        ida_ua.dt_dword:         0xFFFFFFFF,  # 4 bytes
        ida_ua.dt_qword: 0xFFFFFFFFFFFFFFFF,  # 8 bytes
    }

############################################################
# SQL queries
############################################################

sql_lookup_hash_value='''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type;
'''

sql_lookup_hash_type_value='''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type and
    h.hash_type=?;
'''

sql_get_all_hash_types='''
select 
    hash_type,
    hash_size,
    hash_name,
    hash_code
from hash_types;
'''

sql_find_source_lib_by_name='''
select
    lib_key
from 
    source_libs
where 
    lib_name=?;
'''

sql_adjust_cache_size='''
PRAGMA cache_size=200000;
'''

############################################################
# Row wrappers
############################################################

class SymbolHash(object):
    def __init__(self, hashVal, symbolName, libName, hashName, hashSize):
        self.hashVal = hashVal
        self.symbolName = symbolName
        self.libName = libName
        self.hashName = hashName
        self.hashSize = hashSize

    def __str__(self):
        return '%s:0x%08x %s!%s' % (self.hashName, self.hashVal, self.libName, self.symbolName )


class HashType(object):
    def __init__(self, hashType, hashSize, hashName, hashCode):
        self.hashType = hashType
        self.hashSize = hashSize
        self.hashName = hashName
        self.hashCode = hashCode

class HashHit(object):
    def __init__(self, ea, symHash):
        self.ea = ea
        self.symHash = symHash

############################################################
# 
############################################################

class DbStore(object):
    '''
    Used to access the hash db.
    '''
    def __init__(self, dbPath):
        self.dbPath = dbPath
        self.conn = sqlite3.connect(dbPath)
        self.conn.execute(sql_adjust_cache_size)

    def close(self):
        self.conn.close()
        self.conn = None

    def getSymbolByHash(self, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_value, (ctypes.c_int64(hashVal).value,))
        for row in cur:
            #logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

    def getAllHashTypes(self):
        '''
        Returns a list of HashType objects stored in the DB.
        '''
        retArr = []
        cur = self.conn.execute(sql_get_all_hash_types)
        for row in cur:
            retArr.append(HashType(*row))
        return retArr

    def getSymbolByTypeHash(self, hashType, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_type_value, (ctypes.c_int64(hashVal).value, hashType))

        for row in cur:
            #logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

############################################################
# 
############################################################

class SearchParams(object):
    '''
    Just used to track the user provided search parameters.
    '''
    def __init__(self):
        self.searchDwordArray = False
        self.searchPushArgs = False
        self.createStruct = False
        self.useDecompiler = False
        self.useXORSeed = False
        self.XORSeed = 0

        #startAddr & endAddr: range to process
        if using_ida7api:
            self.startAddr = idc.read_selection_start()
            self.endAddr = idc.read_selection_end()
        else:
            self.startAddr = idc.SelStart()
            self.endAddr = idc.SelEnd()

        #hashTypes: list of HashTypes user confirmed to process
        self.hashTypes = []

############################################################
# SearchParams
############################################################

class ShellcodeHashSearcher(object):
    def __init__(self, dbstore, params):
        self.dbstore = dbstore
        self.params = params
        self.hits = []
        self.hitSet = set()
        self.ptrSize = jayutils.getx86CodeSize()/ 8
        logger.debug('Using pointer size: %d bytes', self.ptrSize)

    def addHit(self, ea, sym):
        if ea in self.hitSet:
            return
        self.hits.append(HashHit(ea, sym))
        self.hitSet.add( ea )

    def processCode(self):
        if (self.params.startAddr==idc.BADADDR) and (self.params.endAddr==idc.BADADDR):

            if using_ida7api:
                self.params.startAddr = idc.get_segm_start(idc.here())
                self.params.endAddr = idc.get_segm_end(idc.here())
            else:
                self.params.startAddr = idc.SegStart(idc.here())
                self.params.endAddr = idc.SegEnd(idc.here())
            logger.info('Processing current segment only: 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
        else:
            logger.info('Processing range 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
        if self.params.searchDwordArray:
            self.lookForDwordArray(self.params.startAddr, self.params.endAddr)
        if self.params.searchPushArgs:
            self.lookForOpArgs(self.params.startAddr, self.params.endAddr)

    def processAllSegments(self):
        for seg in idautils.Segments():
            if using_ida7api:
                segStart = idc.get_segm_start(seg)
                segEnd = idc.get_segm_end(seg)
            else:
                segStart = idc.SegStart(seg)
                segEnd = idc.SegEnd(seg)

            if self.params.searchPushArgs:
                self.lookForOpArgs(segStart, segEnd)
            if self.params.searchDwordArray:
                self.lookForDwordArray(segStart, segEnd)

    def run(self):
        logger.info('Starting up')
        self.processCode()
        if self.params.createStruct:
            self.postProcessHits()
        else:
            logger.debug('Skipping create struct')
        self.dbstore.close()
        logger.info('Done')

    def postProcessHits(self):
        '''
        For any consecutive locations of shellocode hits, creates a struct to 
        use as a function pointer table.
        '''
        logger.debug("Starting postProcessHits")
        self.hits.sort(key=lambda x: x.ea)
        count = 0
        start = 0
        for idx, hit in enumerate(self.hits):
            logger.debug('hits[%d]: %08x', idx, hit.ea)
        while start < (len(self.hits)-1):
            prev = start
            curr = start+1
            while ((curr < len(self.hits)) and (self.hits[curr].ea == (self.hits[prev].ea+self.ptrSize))):
                logger.debug('Yes, curr self.hits[%d].ea: %08x, prev self.hits[%d]: %08x', curr, self.hits[curr].ea, prev, self.hits[prev].ea)
                curr, prev = (curr + 1, curr)
            #check if more than 2 consecutive hits, if so: make a struct
            if start != prev:
                logger.debug('Making struct for start: %d - %d', start, curr)
                self.makeStructFromHits(count, start, curr)
                count += 1
            #advance to next section
            start = curr
        logger.debug("Finishing postProcessHits")

    def makeStructFromHits(self, count, startHitIdx, endHitIdx):
        structName = 'sc%d' % count
        logger.debug("Making struct %d:", count)

        if using_ida7api:
            structId = idc.add_struc(0xffffffff, structName, 0)
        else:
            structId = idc.AddStrucEx(0xffffffff, structName, 0)
        if structId == 0xffffffff:
            raise ValueError("Struct %s already exists!" % structName)
        subRange = self.hits[startHitIdx:endHitIdx]
        for i in range(len(subRange)):
            hit = subRange[i]
            logger.debug("%02x: %08x: %08x %s" , i*self.ptrSize, hit.ea, hit.symHash.hashVal, hit.symHash.symbolName)
            if using_ida7api:
                idc.add_struc_member(structId, str(hit.symHash.symbolName), i*self.ptrSize, idc.FF_DATA|idc.FF_DWORD, -1, 4)
            else:
                idc.AddStrucMember(structId, str(hit.symHash.symbolName), i*self.ptrSize, idc.FF_DATA|idc.FF_DWRD, -1, 4)

    def lookForOpArgs(self, start, end):
        for head in idautils.Heads(start, end):
            try:
                for i in range(2):
                    if using_ida7api:
                        t = idc.get_operand_type(head, i)
                    else:
                        t = idc.GetOpType(head, i)
                    if t == idc.o_imm:
                        if using_ida7api:
                            opval = idc.get_operand_value(head, i)
                            insn = idautils.DecodeInstruction(head)
                            opmask = OPERAND_MASK.get(insn.ops[i].dtype)
                            if opmask:
                                opval = opval & opmask
                        else:
                            opval = idc.GetOperandValue(head, i)
                        if self.params.useXORSeed:
                            opval = opval ^ self.params.XORSeed
                        for h in self.params.hashTypes:
                            hits = self.dbstore.getSymbolByTypeHash(h.hashType, opval)
                            for sym in hits:
                                logger.info("0x%08x: %s", head, str(sym))
                                self.addHit(head, sym)
                                self.markupLine(head, sym, self.params.useDecompiler)
            except Exception as err:
               logger.exception("Exception: %s", str(err))

    def addDecompilerComment(self, loc, comment):
        cfunc = idaapi.decompile(loc)
        eamap = cfunc.get_eamap()
        decompObjAddr = eamap[loc][0].ea
        tl = idaapi.treeloc_t()
        tl.ea = decompObjAddr
        commentSet = False
        for itp in range (idaapi.ITP_SEMI, idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
            unused = cfunc.__str__()
            if not cfunc.has_orphan_cmts():
                commentSet = True
                cfunc.save_user_cmts()
                break
            cfunc.del_orphan_cmts()
        if not commentSet:
            print ("pseudo comment error at %08x" % loc)

    def markupLine(self, loc, sym, useDecompiler = False):
        comm = '%s!%s' % (sym.libName, sym.symbolName)
        logger.debug("Making comment @ 0x%08x: %s", loc, comm)
        if using_ida7api:
            idc.set_cmt(loc, str(comm), False)
            if useDecompiler and idaapi.get_func(loc) != None:
                self.addDecompilerComment(loc, str(comm))
        else:
            idc.MakeComm(loc, str(comm))

    def lookForDwordArray(self, start, end):
        logger.debug("Starting to look between: %08x:%08x", start, end)
        for i in range(end-start):
            loc = start + i
            if using_ida7api:
                val = idaapi.get_dword(loc)
            else:
                val = idc.Dword(loc)

            for h in self.params.hashTypes:
                hits = self.dbstore.getSymbolByTypeHash(h.hashType, val)
                for sym in hits:
                    logger.info("0x%08x: %s", loc, str(sym))
                    self.addHit(loc, sym)
                    self.markupLine(loc, sym)

###################################################################
#
###################################################################

class SearchLauncher(object):
    def __init__(self):
        self.params = SearchParams()

    def run(self):
        try:
            logger.debug("Starting up")
            dbFile = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'shellcode_hashes', 'sc_hashes.db'))
            logger.debug('Trying default db path: %s', dbFile)
            if not os.path.exists(dbFile):
                if using_ida7api:
                    dbFile = idaapi.ask_file(False, "*.db", "Select shellcode hash database")
                else:
                    dbFile = idc.AskFile(0, "*.db", "Select shellcode hash database")

                if (dbFile is None) or (not os.path.isfile(dbFile)):
                    logger.debug("No file select. Stopping now")
                    return
            self.dbstore = DbStore(dbFile)
            logger.debug("Loaded db file: %s", dbFile)
            if QT_AVAILABLE:
                self.launchGuiInput()
            else:
                self.launchManualPrompts() 
            searcher = ShellcodeHashSearcher(self.dbstore, self.params)
            logger.debug('Starting to run the searcher now')
            searcher.run()
            logger.debug("Done")
        except RejectionException:
            logger.info('User canceled action')
        except Exception as err:
            logger.exception("Exception caught: %s", str(err))

    def launchGuiInput(self):
        logger.debug('Launching dialog')
        dlg = ShellcodeWidget(self.dbstore, self.params)
        #disable script timeout -> otherwise cancel script dialog pops up
        oldTo = idaapi.set_script_timeout(0)
        res = dlg.exec_()
        #restore the timeout
        idaapi.set_script_timeout(oldTo)
        if res == QtWidgets.QDialog.Accepted:
            logger.debug('Dialog result: accepted')
        elif res == QtWidgets.QDialog.Rejected:
            logger.debug('Dialog result: rejected')
            raise RejectionException()
        else:
            logger.debug('Unknown result')
            raise RuntimeError('Dialog unknown result')

    def launchManualPrompts(self):
        self.promptForSearchTypes()
        self.promptForHashTypes()
        self.promptForRange()

    def promptForHashTypes(self):
        '''
        Iterate over the known hash types in the DB. Prompt the user
        for each one. Kind of painful here since only can do y/n prompt.
        TODO: Find a better/less painful prompt method!
        '''
        # Only run if QT not available, so not bothering with ida7 check
        hashTypes = self.dbstore.getAllHashTypes()
        
	# we used to prompt y/n for each one. too obnoxious, just force all hashes
        self.params.hashTypes = hashTypes

    def promptForSearchTypes(self):
        # Only run if QT not available, so not bothering with ida7 check
        logger.debug("Promping for search types")
        if using_ida7api:
            if idaapi.ASKBTN_YES == idaapi.ask_yn(idaapi.ASKBTN_YES, str('Search for push argument hash values?')):
                self.params.searchPushArgs = True
            if idaapi.ASKBTN_YES == idaapi.ask_yn(idaapi.ASKBTN_YES, str('Search for DWORD array of hashes?')):
                self.params.searchDwordArray = True
        else:
            if idc.AskYN(1, str('Search for push argument hash value?')) == 1:
                self.params.searchPushArgs = True
            if idc.AskYN(1, str('Search for DWORD array of hashes?')) == 1:
                self.params.searchDwordArray = True

        if (not self.params.searchDwordArray) and (not self.params.searchPushArgs):
            raise RuntimeError('No search types selected')

    def promptForRange(self):
        # Only run if QT not available, so not bothering with ida7 check
        #check if a range has already been selected - if so skip prompt
        if using_ida7api:
            selstart = idc.read_selection_start()
            selend = idc.read_selection_end()
            segstart = idc.get_segm_start(idc.here())
            segend = idc.get_segm_end(idc.here())
        else:
            selstart = idc.SelStart()
            selend = idc.SelEnd()
            seg = idc.SegStart(idc.here())
            self.params.endAddr = idc.SegEnd(idc.here())

        if selstart != idc.BADADDR:
            self.params.startAddr = selstart
            self.params.endAddr = selend
            logger.info('Processing range 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
        else:
            self.params.startAddr = segstart
            self.params.endAddr = segend
            logger.info('Processing current segment only')

###################################################################
#
###################################################################

def main():

    launcher = SearchLauncher()
    launcher.run()

if __name__ == '__main__':
    main()
