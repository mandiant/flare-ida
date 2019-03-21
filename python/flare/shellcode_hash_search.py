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
import logging
import os.path
import sqlite3

import idc
import idaapi
import idautils

import jayutils

QT_AVAILABLE = True
try:
    from PyQt5 import QtWidgets, QtCore
    from shellcode_widget import ShellcodeWidget
except ImportError:
    print 'Falling back to simple dialog-based GUI. \nPlease consider installing the HexRays PyQt5 build available at \n"http://hex-rays.com/products/ida/support/download.shtml"'
    QT_AVAILABLE = False


# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (ida_major > 6)

class RejectionException(Exception):
    pass

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
        cur = self.conn.execute(sql_lookup_hash_value, (hashVal,))
        for row in cur:
            #self.logger.debug("Found hits for value: %08x", hashVal)
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
        cur = self.conn.execute(sql_lookup_hash_type_value, (hashVal, hashType))
        for row in cur:
            #self.logger.debug("Found hits for value: %08x", hashVal)
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
    PTR_SIZE = 4
    def __init__(self, dbstore, params):
        self.logger = jayutils.getLogger('ShellcodeHashSearcher')
        self.dbstore = dbstore
        self.params = params
        self.hits = []

    def processCode(self):
        if (self.params.startAddr==idc.BADADDR) and (self.params.endAddr==idc.BADADDR):

            if using_ida7api:
                self.params.startAddr = idc.get_segm_start(idc.here())
                self.params.endAddr = idc.get_segm_end(idc.here())
            else:
                self.params.startAddr = idc.SegStart(idc.here())
                self.params.endAddr = idc.SegEnd(idc.here())
            self.logger.info('Processing current segment only: 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
        else:
            self.logger.info('Processing range 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
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
        self.processCode()
        if self.params.createStruct:
            self.postProcessHits()
        else:
            self.logger.debug('Skipping create struct')
        self.dbstore.close()

    def postProcessHits(self):
        '''
        For any consecutive locations of shellocode hits, creates a struct to 
        use as a function pointer table.
        '''
        self.logger.debug("Starting postProcessHits")
        self.hits.sort(key=lambda x: x.ea)
        count = 0
        start = 0
        while start < (len(self.hits)-1):
            prev = start
            curr = start+1
            while ((curr < len(self.hits)) and (self.hits[curr].ea == (self.hits[prev].ea+self.PTR_SIZE))):
                prev = curr
                curr = prev+1
            #check if more than 2 consecutive hits, if so: make a struct
            if start != prev:
                self.makeStructFromHits(count, start, curr)
                count += 1
            #advance to next section
            start = curr
        self.logger.debug("Finishing postProcessHits")

    def makeStructFromHits(self, count, startHitIdx, endHitIdx):
        structName = 'sc%d' % count
        self.logger.debug("Making struct %d:", count)

        if using_ida7api:
            structId = idc.add_struc(0xffffffff, structName, 0)
        else:
            structId = idc.AddStrucEx(0xffffffff, structName, 0)
        if structId == 0xffffffff:
            raise ValueError("Struct %s already exists!" % structName)
        subRange = self.hits[startHitIdx:endHitIdx]
        for i in range(len(subRange)):
            hit = subRange[i]
            self.logger.debug("%02x: %08x: %08x %s" , i*self.PTR_SIZE, hit.ea, hit.symHash.hashVal, hit.symHash.symbolName)
            if using_ida7api:
                idc.add_struc_member(structId, str(hit.symHash.symbolName), i*self.PTR_SIZE, idc.FF_DATA|idc.FF_DWORD, -1, 4)
            else:
                idc.AddStrucMember(structId, str(hit.symHash.symbolName), i*self.PTR_SIZE, idc.FF_DATA|idc.FF_DWRD, -1, 4)

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
                        else:
                            opval = idc.GetOperandValue(head, i)
                        for h in self.params.hashTypes:
                            hits = self.dbstore.getSymbolByTypeHash(h.hashType, opval)
                            for sym in hits:
                                self.logger.info("0x%08x: %s", head, str(sym))
                                self.hits.append(HashHit(head, sym))
                                self.markupLine(head, sym)
            except Exception, err:
               self.logger.exception("Exception: %s", str(err))

    def markupLine(self, loc, sym):
        comm = '%s!%s' % (sym.libName, sym.symbolName)
        self.logger.debug("Making comment @ 0x%08x: %s", loc, comm)
        if using_ida7api:
            idc.set_cmt(loc, str(comm), False)
        else:
            idc.MakeComm(loc, str(comm))

    def lookForDwordArray(self, start, end):
        self.logger.debug("Starting to look between: %08x:%08x", start, end)
        for i in range(end-start):
            loc = start + i
            if using_ida7api:
                val = idaapi.get_dword(loc)
            else:
                val = idc.Dword(loc)

            for h in self.params.hashTypes:
                hits = self.dbstore.getSymbolByTypeHash(h.hashType, val)
                for sym in hits:
                    self.logger.info("0x%08x: %s", loc, str(sym))
                    self.hits.append(HashHit(loc, sym))
                    self.markupLine(loc, sym)

###################################################################
#
###################################################################

class SearchLauncher(object):
    def __init__(self):
        self.params = SearchParams()
        self.logger = jayutils.getLogger('SearchLauncher')

    def run(self):
        try:
            self.logger.debug("Starting up")
            dbFile = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'shellcode_hashes', 'sc_hashes.db'))
            self.logger.debug('Trying default db path: %s', dbFile)
            if not os.path.exists(dbFile):
                if using_ida7api:
                    dbFile = idc.AskFile(0, "*.db", "Select shellcode hash database")
                else:
                    dbFile = idaapi.ask_file(False, "*.db", "Select shellcode hash database")

                if (dbFile is None) or (not os.path.isfile(dbFile)):
                    self.logger.debug("No file select. Stopping now")
                    return
            self.dbstore = DbStore(dbFile)
            self.logger.debug("Loaded db file: %s", dbFile)
            if QT_AVAILABLE:
                self.launchGuiInput()
            else:
                self.launchManualPrompts() 
            searcher = ShellcodeHashSearcher(self.dbstore, self.params)
            self.logger.debug('Starting to run the searcher now')
            searcher.run()
            self.logger.debug("Done")
        except RejectionException:
            self.logger.info('User canceled action')
        except Exception, err:
            self.logger.exception("Exception caught: %s", str(err))

    def launchGuiInput(self):
        self.logger.debug('Launching dialog')
        dlg = ShellcodeWidget(self.dbstore, self.params)
        #disable script timeout -> otherwise cancel script dialog pops up
        oldTo = idaapi.set_script_timeout(0)
        res = dlg.exec_()
        #restore the timeout
        idaapi.set_script_timeout(oldTo)
        if res == QtWidgets.QDialog.Accepted:
            self.logger.debug('Dialog result: accepted')
        elif res == QtWidgets.QDialog.Rejected:
            self.logger.debug('Dialog result: rejected')
            raise RejectionException()
        else:
            self.logger.debug('Unknown result')
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
        for h in hashTypes:
            if 1 == idc.AskYN(1, str('Include hash: %s' % h.hashName)):
                self.params.hashTypes.append(h)
        if len(self.params.hashTypes) == 0:
            raise RuntimeError('No hashes selected')

    def promptForSearchTypes(self):
        # Only run if QT not available, so not bothering with ida7 check
        self.logger.debug("Promping for search types")
        if idc.AskYN(1, str('Search for DWORD array of hashes?')) == 1:
            self.params.searchDwordArray = True
        if idc.AskYN(1, str('Search for push argument hash value?')) == 1:
            self.params.searchPushArgs = True

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
            self.logger.info('Processing range 0x%08x - 0x%08x', self.params.startAddr, self.params.endAddr)
        else:
            self.params.startAddr = segstart
            self.params.endAddr = segend
            self.logger.info('Processing current segment only')

###################################################################
#
###################################################################

def main():
    #logger = jayutils.configLogger(__name__, logging.DEBUG)
    logger = jayutils.configLogger(__name__, logging.INFO)
    launcher = SearchLauncher()
    launcher.run()

if __name__ == '__main__':
    main()
