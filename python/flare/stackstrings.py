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
########################################################################
# 
# IDA Python script that coalesces & identifies strings manually created
# on the stack. Works for the samples I've seen so far - I'm sure there
# are versions where this doesn't quite work
#
# Replaced my crappy CPU emulation with vivisect. It just works.
#
########################################################################

import os
import pprint
import os.path
import logging
import binascii

import idc
import idaapi
import idautils

import jayutils

try:
    import vivisect
    import envi.bits as e_bits
    from visgraph import pathcore as vg_path
except Exception, err:
    print 'Error importing stuff!'
    raise

# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (ida_major > 6)


#TODO: make option for binary buffers on the stack also?
def stack_track_visitor(node, **kwargs):
    vw = kwargs.get('vw')
    res = kwargs.get('res')
    emu = kwargs.get('emu')
    agg = kwargs.get('agg')
    logger = kwargs.get('logger')
    if (vw is None) or (emu is None) or (logger is None):
        raise RuntimeError('Bad arguments to stack_track_visitor')
    if agg is None:
        agg = StringAccumulator()
    wlog = vg_path.getNodeProp(node, 'writelog')
    for eip, va, bytes in wlog:
        # no longer check if it's writing into a stack memory location or not
        # this allows us to grab manually constructed strings in .data
        # as well
        if eip == 0:
            #logger.debug('Skipping 0 eip: 0x%08x 0x%08x: %s', eip, va, binascii.hexlify(bytes))
            continue
        logger.debug('visiting: 0x%08x: *> 0x%08x 0x%x bytes', eip, va, len(bytes))

        op = vw.parseOpcode(eip)
        if op.getPrefixName().startswith('rep'):
            #ignore rep instructions -> never seen used to acutally construct strings,
            # and causes lots of FPs
            continue
        elif op.mnem.startswith('call'):
            logger.debug('Aggregating due to call: 0x%08x', eip)
            agg.aggregateStack()
        elif all([i == '\x00' for i in bytes]):
            logger.debug('Adding null at 0x%08x: 0x%08x', eip, va)
            agg.addItem((eip, va, bytes))
            if op.mnem.startswith('push'):
                #aggregating based purely on pushes lead to a lot of FPs
                pass
            else:
                agg.aggregateStack()
        elif all( [isAscii(i) for i in bytes]):
            agg.addItem((eip, va, bytes))
            logger.debug('Adding wlog entry: 0x%08x 0x%08x: %s', eip, va, binascii.hexlify(bytes))
        elif all( [isAscii(i) for i in bytes[::2]])  and all([i =='\x00' for i in bytes[1::2]]):
            #just looking for wchar strings made of ascii chars
            agg.addItem((eip, va, bytes))
            logger.debug('Adding possible wchar wlog entry: 0x%08x 0x%08x: %s', eip, va, binascii.hexlify(bytes))
        else:
            logger.debug('Skipping wlog entry: 0x%08x 0x%08x: %s', eip, va, binascii.hexlify(bytes))
    agg.aggregateStack()
    if res is not None:
        #if we're using a local agg, put the results in res
        res.extend(agg.stringDict.values())

#############################################################################

def isAscii(val):
    if isinstance(val, str) or isinstance(val, unicode):
        val = ord(val)
    #if it's printable, or newline, tab
    return ((val >= 0x20) and (val < 0x7f)) or val in [0x0d, 0x0a, 0x09]

################################################################################

class StringAccumulator(object):
    def __init__(self):
        self.logger = jayutils.getLogger('StringAccumulator')
        self.stringDict = {}
        self.stackDict = {}
        self.buffReuseDetected = False

    def addString(self, item):
        entry, string = item
        idx = string.find('\x00')
        if idx >= 0:
            string = string[:idx]
        eip, va, bytes = entry
        if len(self.stringDict.get(eip, ((None,None,None),'') )[1]) < len(string):
            self.logger.debug('Emitting string: 0x%08x: %s', eip, string)
            self.logger.debug('\n    %s', eip, binascii.hexlify(string))
            #self.logger.debug('Current stackDict:\n%s', pprint.pformat(self.stackDict))
            self.stringDict[eip] = item
        else:
            self.logger.debug('Skipping emit: 0x%08x: %s', eip, string)

    def addItem(self, item):
        eip, va, bytes = item
        if self.stackDict.has_key(va):
            self.logger.debug("Possible string overwrite: 0x%08x", eip)
            self.stackDict[va] = item
            self.buffReuseDetected = True
        else:
            self.stackDict[va] = item

    def isAdjacent(self, item1, item2):
        '''Returns True if the two items write to adjacent locations in memory'''
        return item1[1] == (item2[1] + len(item2[2]))

    def isNull(self, item):
        '''Returns True if all bytes in the current write log item are '\x00'''
        eip, va, bytes = item
        return all([i == '\x00' for i in bytes])

    def runStackLength(self, stackLocs, startIdx, endIdx):
        #emit the previous run
        if (endIdx - startIdx) >= 2:
            #self.logger.debug('Joining strings between 0x%08x and 0x%08x', stackLocs[startIdx], stackLocs[endIdx])
            retString = ''.join([self.stackDict[h][2] for h in stackLocs[startIdx:endIdx]])
            if jayutils.isWideString(retString):
                retString = jayutils.extractBasicWideString(retString)
            if retString[-1] == '\x00':
                retString = retString[:-1]
            startTrack = self.stackDict[stackLocs[startIdx]]
            self.addString( (startTrack, retString) )

    def aggregateStack(self):
        #sort by the stack offset
        stackLocs = sorted(self.stackDict.keys())

        currStartIdx = 0
        i = 1
        while i < len(stackLocs):
            #key1 = stackLocs[currStartIdx]
            key1 = stackLocs[i-1]
            key2 = stackLocs[i]
            if self.isAdjacent(self.stackDict[key2], self.stackDict[key1]):
                eip, va, bytes = self.stackDict[key2]
                #self.logger.debug('Found consecutive run: %d %d: %s', currStartIdx, i, binascii.hexlify(bytes))
                #if the current item is a null, emit it & continue
                if self.isNull(self.stackDict[key2]):
                    eip, va, bytes = self.stackDict[key2]
                    self.logger.debug('Found null at 0x%08x: 0x%08x', eip, va)
                    self.runStackLength(stackLocs, currStartIdx, i)
                    #advance beyond null
                    currStartIdx = i+1
            else:
                #emit the previous run
                self.logger.debug('0x%08x is not adjacent to 0x%08x', key1, key2)
                self.runStackLength(stackLocs, currStartIdx, i)
                currStartIdx = i
            i += 1
        #grab last value if still present
        self.runStackLength(stackLocs, currStartIdx, len(stackLocs))

#############################################################################
def runStrings(vw, ea, uselocalagg=True):
    '''
    Returns a list of (write log entry, decoded strings)
    where the write log is the tuple (pc, va, bytes)  
    for the instruction that wrote the first byte of the string
    
    '''
    emu = vw.getEmulator(True, True)

    #modify the stack base for the emulator - smaller mask & frame size
    # wasn't working for funcs with large locals frame size
    emu.stack_map_mask = e_bits.sign_extend(0xfff00000, 4, vw.psize)
    emu.stack_map_base = e_bits.sign_extend(0xbfb00000, 4, vw.psize)
    emu.stack_pointer = emu.stack_map_base + 16*4096

    emu.runFunction(ea, maxhit=1, maxloop=1)
    logger = jayutils.getLogger('stack_graph')

    if uselocalagg:
        #logger.info('Using local agg')
        stringList = []
        jayutils.path_bfs(emu.path, stack_track_visitor, vw=vw, emu=emu, logger=logger, res=stringList )
        return stringList
    else:
        #logger.info('Using global agg')
        agg = StringAccumulator()
        jayutils.path_bfs(emu.path, stack_track_visitor, vw=vw, emu=emu, logger=logger, agg=agg )
        return agg.stringDict.values()

def getFuncRanges(ea, doAllFuncs):
    if using_ida7api:
        return getFuncRanges_ida7(ea, doAllFuncs)
    if doAllFuncs:
        funcs = []
        funcGen = idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea))
        for i in funcGen:
            funcs.append(i)
        funcRanges = []
        for i in range(len(funcs) - 1):
            funcRanges.append( (funcs[i], funcs[i+1]) )
        funcRanges.append( (funcs[-1], idc.SegEnd(ea)) )
        return funcRanges
    else:
        #just get the range of the current function
        fakeRanges = [( idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_START), idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_END)), ]
        return fakeRanges


def getFuncRanges_ida7(ea, doAllFuncs):
    if doAllFuncs:
        funcs = []
        funcGen = idautils.Functions(idc.get_segm_start(ea), idc.get_segm_end(ea))
        for i in funcGen:
            funcs.append(i)
        funcRanges = []
        for i in range(len(funcs) - 1):
            funcRanges.append( (funcs[i], funcs[i+1]) )
        funcRanges.append( (funcs[-1], idc.get_segm_end(ea)) )
        return funcRanges
    else:
        #just get the range of the current function
        fakeRanges = [( idc.get_func_attr(idc.here(), idc.FUNCATTR_START), idc.get_func_attr(idc.here(), idc.FUNCATTR_END)), ]
        return fakeRanges


def isLikelyFalsePositiveString(instr):
    #if a string is all 'A' chars, very likely that it's a false positive
    return all([a == 'A' for a in instr])

def main(doAllFuncs=True):
    #doAllFuncs=False
    #jayutils.configLogger(__name__, logging.DEBUG)
    jayutils.configLogger(__name__, logging.INFO)
    logger = jayutils.getLogger('stackstrings')
    logger.debug('Starting up now')
    filePath = jayutils.getInputFilepath()
    if filePath is None:
        self.logger.info('No input file provided. Stopping')
        return
    vw = jayutils.loadWorkspace(filePath)
    ea = idc.here()
    res = -1
    if using_ida7api:
        res = idc.ask_yn(0, 'Use basic-block local aggregator')
    else:
        res = idc.AskYN(0, 'Use basic-block local aggregator')
    if res == idaapi.ASKBTN_CANCEL:
        print 'User canceled'
        return
    uselocalagg = (res == 1)
    ranges = getFuncRanges(ea, doAllFuncs)
    for funcStart, funcEnd in ranges:
        try:
            logger.debug('Starting on function: 0x%x', funcStart)
            stringList = runStrings(vw, funcStart, uselocalagg)    
            for node, string in stringList:
                if isLikelyFalsePositiveString(string):
                    #if it's very likely a FP, skip annotating
                    continue
                print '0x%08x: %s' % (node[0], string)
                #print '0x%08x: 0x%08x: %s %s' % (node[0], node[1], binascii.hexlify(string), string)
                if using_ida7api:
                    idc.set_cmt(node[0], string.strip(), 0)
                else:
                    idc.MakeComm(node[0], string.strip())
        except Exception, err:
            logger.exception('Error during parse: %s', str(err))
    logger.info("\nDone With function stacks. Starting globals now")


if __name__ == '__main__':
    #main(False)    #testing: only do current function
    main(True)

