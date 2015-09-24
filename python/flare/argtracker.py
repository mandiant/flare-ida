#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
# 
########################################################################
# Copyright 2012 Mandiant
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
# New lib that helps with tracking arguments to functions.
# New version that uses vivisect for analysis
#
########################################################################

import sys
import copy
import struct
import pprint
import logging
import binascii

import jayutils

import vivisect
import vivisect.impemu as viv_imp
import vivisect.impemu.monitor as viv_imp_monitor
from visgraph import pathcore as vg_path

########################################################################
#
#
########################################################################



class RegMonitor(viv_imp_monitor.EmulationMonitor):

    def __init__(self, regs):
        viv_imp_monitor.EmulationMonitor.__init__(self)
        self.logger = jayutils.getLogger('RegMonitor')
        self.regs = regs[:]
        self.reg_map = {}

    def prehook(self, emu, op, starteip):
        #self.reg_map[starteip] = emu.getRegisterSnap()
        try:
            #self.logger.debug('prehook:  0x%08x', starteip)
            #self.cachedRegs = emu.getRegisterSnap()
            self.cachedRegs = emu.getRegisters()
            self.startEip = starteip
            #self.logger.debug('Using cached prehook regs: %s', pprint.pformat(self.cachedRegs))
            #print 'Using cached prehook regs: %s' % pprint.pformat(self.cachedRegs)
        except Exception, err:
            self.logger.exception('Error in prehook: %s', str(err))

    def posthook(self, emu, op, endeip):
        #self.cachedRegs = emu.getRegisterSnap()
        try:
            #self.logger.debug('posthook: 0x%08x', endeip)
            #curRegs = emu.getRegisterSnap()
            curRegs = emu.getRegisters()
            curDict = {}
            #self.logger.debug('Examining current registers: %s', pprint.pformat(curRegs))
            #print 'Examining current registers: %s' % pprint.pformat(curRegs)
            for name, val in curRegs.items():
                #self.logger.debug('     Examining reg: %s', name)
                #if name in self.regs and self.cachedRegs.has_key(name) and (self.cachedRegs[name] != val):
                if name in self.regs and (self.cachedRegs[name] != val):
                    curDict[name] = val
                    self.logger.debug('Found overwritten reg: %s:=0x%x', name, val)
            if len(curDict) != 0:
                self.reg_map[self.startEip] = curDict
        except Exception, err:
            self.logger.exception('Error in posthook: %s', str(err))
        

########################################################################
#
#
########################################################################

#maps a va to the vg_path node that contains it in an emu run
def build_emu_va_map(node, **kwargs):
    res = kwargs.get('res')
    emu = kwargs.get('emu')
    if res is None or emu is None:
        return
    #for va in vg_path.getNodeProp(node, 'valist'):
    #    res[va] = node
    #for pc, va, bytes in vg_path.getNodeProp(node, 'writelog'):
    for entry in vg_path.getNodeProp(node, 'writelog'):
        pc, va, bytes = entry
        res[pc] = entry


def formatWriteLogEntry(entry):
    pc, va, bytes = entry
    return '0x%08x: 0x%08x: %s' % (pc, va, binascii.hexlify(bytes))

class ArgTracker(object):

    def __init__(self, vw):
        self.logger = jayutils.getLogger('ArgTracker')
        self.logger.debug('Starting up here')
        self.vw = vw
        self.lastFunc = 0
        self.va_write_map = None
        self.codesize = jayutils.getx86CodeSize()
        self.ptrsize = self.codesize/8

    def printWriteLog(self, wlog):
        for ent in wlog:
            self.logger.debug(formatWriteLogEntry(ent))

    def isCargsComplete(self, cargs, num, regs):
        return all([cargs.has_key(i+1) for i in range(num)]) and all([cargs.has_key(i) for i in regs])

    def getPushArgs(self, va, num, regs=[]):
        '''
        num -> first arg is 1, 2nd is 2, ...
        
        Returns a list of dicts whose key is the arg number (starting at 1, 2.. num)
        Each dict entry is a write log tuple (pc, va bytes)
        
        '''
        count = 0
        ret = []
        touched = []
        func = self.vw.getFunction(va)
        if func is None:
            self.logger.error('Could not get function start from vw 0x%08x -> has analysis been done???', va)
            return ret
        #map a every (?) va in a function to the pathnode it was found in
        if func != self.lastFunc:
            emu = self.vw.getEmulator(True, True)
            self.logger.debug('Generating va_write_map for function 0x%08x', func)
            if len(regs) == 0:
                self.regMon = None
            else:
                self.regMon = RegMonitor(regs)
                emu.setEmulationMonitor(self.regMon)
            emu.runFunction(func, maxhit=1, maxloop=1)
            #cache the last va_write_map for a given function
            self.va_write_map = {}
            self.lastFunc = func
            jayutils.path_bfs(emu.path, build_emu_va_map, res=self.va_write_map, emu=emu)
        else:
            self.logger.debug('Using cached va_write_map')
        self.logger.debug('Len va_write_map: %d', len(self.va_write_map))
        baseEntry = self.va_write_map.get(va, None)
        if baseEntry is None:
            self.logger.error('Node does not have write log. Requires a call instruction (which writes to the stack) for this to work: 0x%08x', va)
            return ret
        startSp = baseEntry[1]
        desiredSp = [startSp + self.ptrsize*(1+i) for i in range(num)]
        self.logger.debug('Starting SP: 0x%08x', startSp)
        self.logger.debug('Desired SP: %s', ' '.join([hex(i) for i in desiredSp]))
        queue = [ (va, {}) ]
        while len(queue) != 0:
            #if count > 2000:
            if count > 100:
                self.logger.error('Error in graph traversal: loop count = %d', count)
                break
            cVa, cArgs = queue.pop(0)
            self.logger.debug('Examining 0x%08x: %s' , cVa, str(cArgs))
            wlogEntry = self.va_write_map.get(cVa, None)
            if (wlogEntry is not None) and (wlogEntry[1] in desiredSp):
                argNum = (wlogEntry[1] - startSp)/self.ptrsize
                self.logger.debug('Examining argnum %d at wlogEntry:', argNum)
                self.logger.debug('%s', formatWriteLogEntry(wlogEntry))
                if not cArgs.has_key(argNum):
                    cArgs[argNum] = wlogEntry
                #if argNum == num:
                #    self.logger.debug('Yep, appending')
                #    ret.append(cArgs)
                #else:
                #    self.logger.debug('Nope: %d is not %d. Queuing prev items' , argNum, num)
                #    for lva, lsize, ltype, linfo in jayutils.getAllXrefsTo(self.vw, cVa):
                #        queue.append( (lva, copy.copy(cArgs)) )

            if (self.regMon is not None) and (self.regMon.reg_map.has_key(cVa)):
                #figure out if one of the monitored regs is modified in this instruction
                # and if has not already been stored -> just want the first reg value
                regMods = self.regMon.reg_map[cVa]
                for reg in regs:
                    if regMods.has_key(reg) and not cArgs.has_key(reg):
                        cArgs[reg] = regMods[reg]
                        self.logger.debug('Found reg: %s: 0x%x', reg, regMods[reg])

            if self.isCargsComplete(cArgs, num, regs):
                self.logger.debug('Yep, appending')
                ret.append(cArgs)
            else:
                #else queue all xrefs to this piece
                # orange TODO: limit xref type????? - prevent accidentally leaving function??
                # orange TODO: filter out calls to current inst & ignore??
                self.logger.debug('Not complete: queuing prev items')
                for lva, lsize, ltype, linfo in jayutils.getAllXrefsTo(self.vw, cVa):
                    queue.append( (lva, copy.copy(cArgs)) )
            #orange TODO: need to prevent/detect looping??!?!?!
            #if cVa in touched:
            #    continue
            count += 1
        return ret


def main():
    #jayutils.configLogger(None, logging.DEBUG)
    jayutils.configLogger(None, logging.INFO)
    logger = jayutils.getLogger('')
    logger.debug('Starting up in main')
    #name = idc.AskStr('CreateThread', 'Enter function to find args for')
    #name = idc.AskStr('CreateThread', 'Enter function to find args for')
    #argNum = idc.AskLong(6)

    filePath = jayutils.getInputFilepath()
    if filePath is None:
        self.logger.info('No input file provided. Stopping')
        return
    vw = jayutils.loadWorkspace(filePath)
    logger.debug('Loaded workspace')
    tracker = ArgTracker(vw)

    import idautils
    funcEa = idc.LocByName('CreateThread')
    if funcEa == idc.BADADDR:
        logger.info('CreateThread not found. Returning now')
        return
    for xref in idautils.XrefsTo(funcEa):
        argsList = tracker.getPushArgs(xref.frm, 6)
        for argDict in argsList:
            print '-'*60
            wlog = argDict[3]
            print '0x%08x: 0x%08x: 0x%08x' % (xref.frm, wlog[0], struct.unpack_from('<I', wlog[2])[0])

if __name__ == '__main__':
    main()

