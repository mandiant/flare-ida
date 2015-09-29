#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2015 FireEye
# Copyright 2012 Mandiant
#
# FireEye licenses this file to you under the Apache License, Version
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

import idc
import idaapi
import idautils

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
                    #self.logger.debug('0x%08x: Found overwritten reg: %s:=0x%x', self.startEip, name, val)
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
    logtype = kwargs.get('logtype')
    if (res is None) or (emu is None) or (logtype is None):
        return
    #for va in vg_path.getNodeProp(node, 'valist'):
    #    res[va] = node
    #for pc, va, bytes in vg_path.getNodeProp(node, 'writelog'):
    for entry in vg_path.getNodeProp(node, logtype):
        pc, va, bytes = entry
        res[pc] = entry


def formatWriteLogEntry(entry):
    pc, va, bytes = entry
    return '0x%08x: 0x%08x: %s' % (pc, va, binascii.hexlify(bytes))

def transformWriteLogEntry(entry, bigend=False):
    '''
    Tranforms a writelog entry to a (pc, value) tuple
    '''
    pc, va, bytes = entry
    blen = len(bytes)
    if blen == 1:
        return (pc, struct.unpack_from('<B', bytes)[0])
    elif blen == 2:
        return (pc, struct.unpack_from('<H', bytes)[0])
    elif blen == 4:
        return (pc, struct.unpack_from('<I', bytes)[0])
    elif blen == 8:
        return (pc, struct.unpack_from('<Q', bytes)[0])
    elif blen == 16:
        t0,t1 =  struct.unpack_from('<QQ', bytes)[0]
        return (pc, (t1<<64) | t0)
    else:
        raise RuntimeError('Unexpected len of writelog bytes: %d' % blen)

class TrackerState(object):
    def __init__(self, tracker, baseEntry, num, regs):
        '''
        desiredState: list of stackArgNums and register names
        '''
        self.tracker = tracker
        self.baseEntry = baseEntry
        self.num = num
        self.regs = regs[:]
        self.ptrsize = tracker.ptrsize
        self.resultArgs = {}

        #stackArgLocs: pre-calculated locations we're looking for for stack writes
        self.stackArgLocs = []

        #tempMapping: used to follow data movement backwards. if a value we're interested
        # in is loaded in another register or a memory location, maps the current
        self.tempMapping = {}

        #desiredState: list of stackArgNums and register names
        self.desiredState = []

        self.setDesiredState(baseEntry, num, regs)
        self.setStackArgLocs(baseEntry, num, regs)

    def copy(self):
        cp = TrackerState(self.tracker, self.baseEntry, self.num, self.regs)
        cp.resultArgs = copy.deepcopy(self.resultArgs)
        cp.tempMapping = copy.deepcopy(self.tempMapping)
        cp.desiredState = copy.deepcopy(self.desiredState)
        return cp

    def __str__(self):
        info = '\n'.join([ '%s: %s,' % (self.getArgNameRep(k), repr(self.resultArgs.get(k))) for k in self.desiredState])
        return info

    def processWriteLog(self, tracker, cVa):
        wlogEntry = tracker.va_write_map.get(cVa, None)
        if (wlogEntry is None):
            return
        pc, writeVa, bytes = wlogEntry
        if (writeVa in self.stackArgLocs) and (self.getStackArgNum(writeVa) not in self.resultArgs.keys()):
            #it's a stack arg value
            pc, value = transformWriteLogEntry(wlogEntry)
            self.tracker.logger.debug('writelog 0x%08x: Found stack arg %d: 0x%08x', pc, self.getStackArgNum(writeVa), value)
            self.saveResult(writeVa, pc, value)
            return

        if writeVa not in self.tempMapping.keys():
            self.tracker.logger.debug('writelog 0x%08x: not interesting', pc)
            return

        #argName: the actual value we're tracing back
        argName = self.tempMapping.pop(writeVa)
        pc, value = transformWriteLogEntry(wlogEntry)

        #we found a temp value tracing backwards, but need to determine if it's a constant
        # or if we need to continue tracing backwards. basically as long as it's not
        # a register, we stop?
        mnem = idc.GetMnem(pc)
        srcOpIdx = 0
        if mnem.startswith('push'):
            srcOpIdx = 0
        elif mnem.startswith('mov'):
            srcOpIdx = 1
        else:
            #TODO: any other data movement instructions need to be traced rahter
            # than using the observed write log value?
            self.tracker.logger.debug('writelog 0x%08x: found (default): 0x%08x', pc, value)
            self.saveResult(argName, pc, value)
            return

        #process data movements instructions:
        optype = idc.GetOpType(pc, srcOpIdx)
        if optype == idc.o_reg:
            #need to trace the new reg now
            newReg = idc.GetOpnd(pc, srcOpIdx)
            self.tracker.logger.debug('writelog 0x%08x tracing: (%s): %s', pc, self.getArgNameRep(argName), newReg)
            self.tempMapping[newReg] = argName
        else:
            #not a register, so currently assuming we can use the stored value
            self.tracker.logger.debug('writelog 0x%08x: found (non-reg): 0x%08x', pc, value)
            self.saveResult(argName, pc, value)

    def getArgNameRep(self, argName):
        if isinstance(argName, int) or isinstance(argName, long):
            return '0x%08x' % argName
        return argName

    def getStackArgNum(self, writeVa):
        return (writeVa - self.startSp)/self.ptrsize
                
    def saveResult(self, argName, pc, value):
        '''
        Saves a tuple (pc, value) to the found argument.
        Assumes if argName is an integer, it's the address of an expected stack argument.
        If argName is a string, it's a register name for an expected argument.
        '''
        if isinstance(argName, int) or isinstance(argName, long) :
            #argNum = (wlogEntry[1] - self.startSp)/tracker.ptrsize
            argNum = self.getStackArgNum(argName)
            self.resultArgs[argNum] = (pc, value)
        elif isinstance(argName, str):
            self.resultArgs[argName] = (pc, value)
        else:
            raise RuntimeError('Unknown argName type: %s' % type(argName))

    def processRegMon(self, tracker, cVa):
        if tracker.regMon is None:
            tracker.logger.debug('regmon: regMon is empty')
            return
        regMods = tracker.regMon.reg_map.get(cVa)
        if regMods is None:
            tracker.logger.debug('regmon 0x%08x: no entry in reg_map', cVa)
            return
        #figure out if one of the monitored regs is modified in this instruction
        # and if has not already been stored -> just want the first reg value
        regMods = self.tracker.regMon.reg_map[cVa]
        self.tracker.logger.debug('regmon 0x%08x: examining %d items: %r', cVa, len(regMods), regMods)
        for reg in regMods:
            interesting1 = (reg in self.regs) and (reg not in self.resultArgs.keys())
            interesting2 = (reg in self.tempMapping.keys())
            if (not interesting1) and (not interesting2):
                #modified reg isn't interesting: either a function arg or a temp traced value
                self.tracker.logger.debug('regmon 0x%08x: not interesting: %s', cVa, reg)
                continue
            mnem = idc.GetMnem(cVa)
            argName = reg
            if interesting1:
                self.regs.remove(reg)
            if interesting2:
                argName = self.tempMapping.pop(reg)
            if mnem.startswith('pop'):
                #add the current stack read address to the temporary tracking
                rlogEntry = tracker.va_read_map.get(cVa, None)
                if rlogEntry is None:
                    raise RuntimeError('readlog entry does not exist for a pop')
                pc, readVa, bytes = rlogEntry
                self.tracker.logger.debug('regmon 0x%08x tracing (pop): %s (%s): 0x%x', cVa, argName, reg, readVa)
                self.tempMapping[readVa] = argName
            elif mnem.startswith('mov'):
                if idc.GetOpType(cVa, 1) == idc.o_reg:
                    #change to track this reg backwards
                    newReg = idc.GetOp
                    self.tracker.logger.debug('regmon 0x%08x tracing (mov): %s (%s)', cVa, argName, reg)
                    self.tempMapping[newReg] = argName
                else:
                    #not a register, use the modified result otherwise?
                    self.tracker.logger.debug('regmon 0x%08x found (mov): %s (%s): 0x%x', cVa, argName, reg, regMods[reg])
                    self.saveResult(argName, cVa, regMods[reg])
            else:
                #TODO: any other data movement instructions that should be traced back?
                self.tracker.logger.debug('regmon 0x%08x found (default): %s (%s): 0x%x', cVa, argName, reg, regMods[reg])
                self.saveResult(argName, cVa, regMods[reg])

    def setStackArgLocs(self, baseEntry, num, regs):
        self.startSp = baseEntry[1]
        # desiredSp: the stack write addressses that correspond to the arguments we want
        self.stackArgLocs = [self.startSp + self.ptrsize*(1+i) for i in range(num)]

    def setDesiredState(self, baseEntry, num, regs):
        desiredState = [(i+1) for i in range(num)]
        desiredState.extend(regs)
        self.desiredState = sorted(desiredState)

    def isComplete(self):
        if len(self.desiredState) == len(self.resultArgs):
            if self.desiredState == sorted(self.resultArgs.keys()):
                return True
            else:
                raise RuntimeError('Matching len of resultArgs, but not equal!')
        return False

class ArgTracker(object):

    def __init__(self, vw):
        self.logger = jayutils.getLogger('ArgTracker')
        self.logger.debug('Starting up here')
        self.vw = vw
        self.lastFunc = 0
        self.va_write_map = None
        self.codesize = jayutils.getx86CodeSize()
        self.ptrsize = self.codesize/8
        self.queue = []

    def printWriteLog(self, wlog):
        for ent in wlog:
            self.logger.debug(formatWriteLogEntry(ent))

    def isCargsComplete(self, cargs, num, regs):
        return all([cargs.has_key(i+1) for i in range(num)]) and all([cargs.has_key(i) for i in regs])


    def getPushArgs(self, va, num, regs=None):
        '''
        num -> first arg is 1, 2nd is 2, ...
        
        Returns a list of dicts whose key is the arg number (starting at 1, 2.. num)
        Each dict for a stack argument is a write log tuple (pc, va bytes)
        Each dict for a registry is a tuple (pc, value)
        
        '''
        if regs is None:
            regs = []
        count = 0
        touched = []

        #func = self.vw.getFunction(va)
        #if func is None:
        #    self.logger.error('Could not get function start from vw 0x%08x -> has analysis been done???', va)
        #    return []
        funcStart = idc.GetFunctionAttr(va, idc.FUNCATTR_START)
        #if func != funcStart:
        #    self.logger.error('IDA & vivisect disagree over function start. Needs to be addressed before process')
        #    self.logger.error(' IDA: 0x%08x. vivisect: 0x%08x', funcStart, func)
        #    return []
        #map a every (?) va in a function to the pathnode it was found in
        if funcStart != self.lastFunc:
            emu = self.vw.getEmulator(True, True)
            self.logger.debug('Generating va_write_map for function 0x%08x', funcStart)
            #if len(regs) == 0:
            #    self.regMon = None
            #else:
            #    self.regMon = RegMonitor(regs)
            #    emu.setEmulationMonitor(self.regMon)
            self.regMon = RegMonitor(regs)
            emu.setEmulationMonitor(self.regMon)
            emu.runFunction(funcStart, maxhit=1, maxloop=1)
            #cache the last va_write_map for a given function
            self.va_write_map = {}
            self.va_read_map = {}
            self.lastFunc = funcStart
            jayutils.path_bfs(emu.path, build_emu_va_map, res=self.va_write_map, emu=emu, logtype='writelog')
            jayutils.path_bfs(emu.path, build_emu_va_map, res=self.va_read_map, emu=emu, logtype='readlog')
        else:
            self.logger.debug('Using cached va_write_map')
        #self.logger.debug('Len va_write_map: %d', len(self.va_write_map))
        #for cVa, wlog in self.va_write_map.items():
        #    self.logger.debug('0x%08x: %s', cVa, formatWriteLogEntry(wlog))

        baseEntry = self.va_write_map.get(va, None)
        if baseEntry is None:
            self.logger.error('Node does not have write log. Requires a call instruction (which writes to the stack) for this to work: 0x%08x', va)
            return []
        self.startSp = baseEntry[1]

        #initState = self.getInitTrackerState(baseEntry, num, regs)
        #initState = TrackerState(baseEntry, num, regs)

        #startSp = baseEntry[1]
        ## desiredSp: the stack write addressses that correspond to the arguments we want
        #desiredSp = [startSp + self.ptrsize*(1+i) for i in range(num)]
        #self.logger.debug('Starting SP: 0x%08x', startSp)
        #self.logger.debug('Desired SP: %s', ' '.join([hex(i) for i in desiredSp]))

        return self.analyzeTracker(baseEntry, va, num, regs)

        ##queue is a tuple of (address, 
        #queue = [ (va, {}) ]
        #while len(queue) != 0:
        #    #if count > 2000:
        #    if count > 100:
        #        self.logger.error('Error in graph traversal: loop count = %d', count)
        #        break
        #    cVa, cArgs = queue.pop(0)
        #    self.logger.debug('Examining 0x%08x: %s' , cVa, str(cArgs))
        #    wlogEntry = self.va_write_map.get(cVa, None)
        #    if (wlogEntry is not None) and (wlogEntry[1] in desiredSp):
        #        argNum = (wlogEntry[1] - startSp)/self.ptrsize
        #        self.logger.debug('Examining argnum %d at wlogEntry:', argNum)
        #        self.logger.debug('%s', formatWriteLogEntry(wlogEntry))
        #        if not cArgs.has_key(argNum):
        #            cArgs[argNum] = wlogEntry
        #        #if argNum == num:
        #        #    self.logger.debug('Yep, appending')
        #        #    ret.append(cArgs)
        #        #else:
        #        #    self.logger.debug('Nope: %d is not %d. Queuing prev items' , argNum, num)
        #        #    for lva, lsize, ltype, linfo in jayutils.getAllXrefsTo(self.vw, cVa):
        #        #        queue.append( (lva, copy.copy(cArgs)) )

        #    if (self.regMon is not None) and (self.regMon.reg_map.has_key(cVa)):
        #        #figure out if one of the monitored regs is modified in this instruction
        #        # and if has not already been stored -> just want the first reg value
        #        regMods = self.regMon.reg_map[cVa]
        #        for reg in regs:
        #            if regMods.has_key(reg) and not cArgs.has_key(reg):
        #                cArgs[reg] = (cVa, regMods[reg])
        #                self.logger.debug('Found reg: %s: 0x%x', reg, regMods[reg])

        #    if self.isCargsComplete(cArgs, num, regs):
        #        self.logger.debug('Yep, appending')
        #        ret.append(cArgs)
        #    else:
        #        #else queue all xrefs to this piece
        #        # orange TODO: limit xref type????? - prevent accidentally leaving function??
        #        # orange TODO: filter out calls to current inst & ignore??
        #        self.logger.debug('Not complete: queuing prev items')
        #        for lva, lsize, ltype, linfo in jayutils.getAllXrefsTo(self.vw, cVa):
        #            queue.append( (lva, copy.copy(cArgs)) )
        #    #orange TODO: need to prevent/detect looping??!?!?!
        #    #if cVa in touched:
        #    #    continue
        #    count += 1
        #return self.ret

    def analyzeTracker(self, baseEntry, va, num, regs):
        funcStart = idc.GetFunctionAttr(va, idc.FUNCATTR_START)
        initState = TrackerState(self, baseEntry, num, regs)
        count = 0
        ret = []
        self.queue = [ (va, initState) ]
        while len(self.queue) != 0:
            if count > 500:
                self.logger.error('Max graph traversal reached: %d', count)
                break
            cVa, cState = self.queue.pop(0)
            self.logger.debug('Examining 0x%08x: %s' , cVa, str(cState))
            try:
                cState.processWriteLog(self, cVa)
                self.logger.debug('writelog 0x%08x done', cVa)
                cState.processRegMon(self, cVa)
                self.logger.debug('regmon 0x%08x done', cVa)
            except Exception, err:
                self.logger.exception('Error in process: %s', str(err))
                return []
            if cState.isComplete():
                self.logger.debug('Yep, appending')
                ret.append(cState.resultArgs)
            else:
                if cVa == funcStart:
                    self.logger.debug('Skipping xref queueing: hit function start')
                else:
                    self.logger.debug('Not complete: queuing prev items')
                    for ref in idautils.CodeRefsTo(cVa, True):
                        self.logger.debug('Queueing 0x%08x -> 0x%08x', cVa, ref)
                        self.queue.append( (ref, cState.copy()) )
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

