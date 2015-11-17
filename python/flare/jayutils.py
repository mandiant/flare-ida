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
# Common util functions for IDA scripts.
#
########################################################################


import os
import re
import sys
import types
import logging
import os.path

import idc
import idaapi
import idautils
import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore",category=DeprecationWarning)

def isWideString(inStr):
    return (len(inStr) >= 2) and (inStr[0] != '\x00') and (inStr[1] == '\x00')

def extractBasicWideString(inStr):
    return inStr[::2]

def isValidPointer(va):
    for segStart in idautils.Segments():
        if (va >= segStart) and (va < idc.SegEnd(segStart)):
            return True
    return False

def getString(ea, maxLen=0x200):
    '''Returns up to 0x200 bytes, until a null is found'''
    i = 0
    retList = []
    while i < maxLen:
        b = idc.Byte(ea+i)
        if b == 0x00:
            break
        retList.append(chr(b))
        i += 1
    return ''.join(retList)

HARD_NAME_RE = re.compile(r'''(\w+)_(\d+)''')
def makeNameHard(ea, name):
    '''Keeps trying to name the given ea until it works, adding the optional _%d suffix'''
    count = 0
    ret = idc.MakeNameEx(ea, name, idc.SN_PUBLIC|idc.SN_NOWARN)
    m = HARD_NAME_RE.match(name)
    if m is not None:
        #already a name in <name>_<count>  format
        name, count = m.group(1,2)
        count = int(count)
    if ret == 0:
        while (count < 100) and (ret == 0):
            newName = '%s_%d' % (name, count)
            ret = idc.MakeNameEx(ea, newName, idc.SN_PUBLIC|idc.SN_NOWARN)
            count += 1
 
def getx86CodeSize(ea=None):
    '''
    For a given EA, finds the code size. Returns 16 for-16bit, 32 for 32-bit, or 64 for 64-bit.
    If no EA is given, searches through all segments for a code segment to use.
    '''
    if ea is None:
        for seg in idautils.Segments():
            if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == idc.SEG_CODE:
                ea = seg
                break
    if ea is None:
        raise RuntimeError('Could not find code segment to use for getx86CodeSize')
    bitness = idc.GetSegmentAttr(ea, idc.SEGATTR_BITNESS)
    if bitness == 0:
        return 16
    elif bitness == 1:
        return 32
    elif bitness == 2:
        return 64
    raise RuntimeError('Bad bitness')

 
###############################################################################
# Config loggers and add hex dumps to the logger
###############################################################################

def configLogger(rootname=None, level=logging.INFO, customLevels=None):
    logger = logging.getLogger(rootname)
    if len(logger.handlers) != 0:
        return logger
    logger = logging.getLogger(rootname)
    logger.setLevel(level)
    formatter = logging.Formatter("%(name)s: %(message)s")
    errStream = logging.StreamHandler(sys.stdout)
    errStream.handleError = handleErrorRaiseError
    errStream.setFormatter(formatter)
    logger.addHandler(errStream)
    if customLevels is not None:
        for logName, logLevel in customLevels:
            tmpLog = getLogger(logName)
            tmpLog.setLevel(logLevel)
    return getLogger(rootname)


def handleErrorRaiseError(record):
    raise

def _getPrintChar(c):
    if (ord(c) >= 0x20) and (ord(c) <= 0x7e):
        return c
    return '.'

def _formatLine(num, inBytes):
    hexBytes = []
    ascBytes = []
    for i in range(16):
        if ((i%2) == 0) and (i!=0):
            hexBytes.append(' ')
        if i < len(inBytes):
            #print "Using len(inBytes): %d, i %d" % (len(inBytes), i)
            hexBytes.append('%02x' % ord(inBytes[i]))
            ascBytes.append(_getPrintChar(inBytes[i]))
        else:
            hexBytes.append('  ')
    return "%04x: %s %s" % (num, ''.join(hexBytes), ''.join(ascBytes))


def doHexLog(self, level, inBytes, msg='', *args, **kwargs):
    if not self.isEnabledFor(level):
        return
    lines = ['\n']
    #lines = []
    hexLine = []
    base = 0
    if len(inBytes) == 0:
        self.log(level, msg, *args, **kwargs)
        return 
    #turn int array into string
    if isinstance(inBytes[0], int):
        inBytes = ''.join([chr(x) for x in inBytes])
    for i in range(len(inBytes)):
        if ((i % 16) == 0) and (i != 0):
            lines.append(_formatLine(base, hexLine))
            hexLine = []
            base = i
        hexLine.append(inBytes[i])
    if len(hexLine) != 0:
        lines.append(_formatLine(base, hexLine))
    self.log(level, msg, *args, **kwargs)
    self.log(level, '\n'.join(lines))

def debugHex(self, inBytes, msg, *args, **kwargs):
     self.doHexLog(logging.DEBUG, inBytes, msg, *args, **kwargs)

def infoHex(self, inBytes, msg, *args, **kwargs):
     self.doHexLog(logging.INFO, inBytes, msg, *args, **kwargs)

def warningHex(self, inBytes, msg, *args, **kwargs):
     self.doHexLog(logging.WARNING, inBytes, msg, *args, **kwargs)

def errorHex(self, inBytes, msg, *args, **kwargs):
     self.doHexLog(logging.ERROR, inBytes, msg, *args, **kwargs)
       
############################################################
# add hexprinting to existing loggers that obey logging level semantics
def getLogger(name=None):
    logger = logging.getLogger(name)
    logger.doHexLog = types.MethodType(doHexLog, logger)
    logger.debugHex = types.MethodType(debugHex, logger)
    logger.infoHex = types.MethodType(infoHex, logger)
    logger.warningHex = types.MethodType(warningHex, logger)
    logger.errorHex = types.MethodType(errorHex, logger)
    return logger

######################################################################
# IDB persistent storage wrappers
######################################################################


#my own personal netnode name
NETNODE_NAME = '$ jayutils'

VIV_WORKSPACE_NAME = 'viv_workspace_path'

def getInputFilepath():
    '''Returns None if the uesr cancels. Updates the filepath in the idb on success'''
    filePath = idc.GetInputFilePath()
    if not os.path.exists(filePath):
        print 'IDB input file not found. Prompting for new one: %s' % filePath
        filePath = idc.AskFile(False, '*.*', 'Enter path to idb input file')
        if filePath is not None:
            idc.SetInputFilePath(filePath)
    return filePath

def loadWorkspace(filename, fast=False):
    import vivisect
    logger = getLogger('loadWorkspace')
    # haha - screw you ida! storing values in idaapi works - you cache yourselves but not me
    #cacheDict = getattr(sys.modules['idaapi'], 'vw_cached_workspace', None)
    cacheDict = None
    if filename is None:
        return None

    if cacheDict is None:
        cacheDict = {}
        logger.info('No vw cache present.')
        setattr(sys.modules['idaapi'], 'vw_cached_workspace', cacheDict)
    else:
        vw = cacheDict.get(filename)
        if vw is None:
            logger.info('Got cache dict, but workspace not present')
        else:
            logger.info('Got vw from cached global value!')
            return vw
    vw = vivisect.VivWorkspace()
    vivName = queryIdbNetnode(VIV_WORKSPACE_NAME)
    if vivName is None or not os.path.exists(vivName):
        vivName = filename + '.viv'
        if os.path.exists(vivName):
            logger.info('Loading existing workspace %s', vivName)
            sys.stdout.flush()
            vw.loadWorkspace(vivName)
        else:
            logger.info('Loading file into vivisect: %s', filename)
            sys.stdout.flush()
            vw.loadFromFile(filename)
            if not fast:
                logger.info('Performing vivisect analysis now. This may take some time...')
                logger.info('#'*80)
                vw.analyze()
                logger.info('#'*80)
                logger.info('Analysis done. Continuing now')
            vw.saveWorkspace()
        #store the .viv filepath in the IDB for later use
        setIdbNetnode(VIV_WORKSPACE_NAME, vw.getMeta("StorageName"))
        logger.info('Stored .viv workspace to: %s', queryIdbNetnode(VIV_WORKSPACE_NAME))
    else:
        logger.info('Found .viv name from idb netnode. Loading %s', vivName)
        vw.loadWorkspace(vivName)
    logger.info('Caching vw workspace object in global variable now')
    cacheDict[filename] = vw
    return vw


def queryIdbNetnode(key):
    n = idaapi.netnode(NETNODE_NAME, len(NETNODE_NAME), True)
    return n.hashval(key)

def setIdbNetnode(key, value):
    n = idaapi.netnode(NETNODE_NAME, len(NETNODE_NAME), True)
    return n.hashset(key, value)


######################################################################
# visgraph traversal helpers
######################################################################


#orange TODO: path funtions aren't checking for duplicating traversal
# since doing there's no path node ID, and doing a straight node-cmp
# is too much

def path_dfs(node, func, **kwargs):
    todo = [node]
    while len(todo) != 0:
        #node is a tuple of (parent, child_list, prop_dict)
        cur = todo.pop(0)
        #insert children at start of queue
        blah = cur[1][:]
        blah.extend(todo)
        todo = blah
        func(cur, **kwargs)
 
def path_bfs(node, func, **kwargs):
    todo = [node]
    while len(todo) != 0:
        #node is a tuple of (parent, child_list, prop_dict)
        cur = todo.pop(0)
        #append children to end of queue
        todo.extend(cur[1])
        func(cur, **kwargs)

######################################################################
# vivisect helpers 
######################################################################


# fall-through code refs aren't put in the visi xrefs, so manually
# do that here
def getAllXrefsTo(vw, va):
    import vivisect
    #manually parse the preceding instruction & look to see if it can fall through to us
    #make a copy of the xrefs!!! or badness will ensue
    init = vw.getXrefsTo(va)[:]
    prev = vw.getPrevLocation(va)
    if prev is None:
        return init
    lva, lsize, ltype, linfo = prev
    if ltype != vivisect.const.LOC_OP:
        return init
    try:
        op = vw.parseOpcode(lva)
    except Exception:
        print 'Weird error while doing getAllXrefsTo: %s' % str(err)
        return init
    brlist = op.getBranches()
    for tova,bflags in brlist:
        if tova == va:
            init.append( (lva, tova, vivisect.const.REF_CODE, bflags) )
    return init



