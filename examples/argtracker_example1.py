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
# gh0st custom thread runner identifier. Written for: 22958062524bb2a9dd6cf300d6ff4816
#
# gh0st variants tend to use a custom launcher for threads. This searches
# for a single xref to _beginthreadex, and then 
#
# 
# This expects the custom thread launcher to look like:
# HANDLE MyCreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, // SD
#                        SIZE_T dwStackSize,                       // initial stack size
#                        LPTHREAD_START_ROUTINE lpStartAddress,    // thread function
#                        LPVOID lpParameter,                       // thread argument
#                        DWORD dwCreationFlags,                    // creation option
#                        LPDWORD lpThreadId, bool bInteractive);
#
########################################################################

import idc
import idaapi
import idautils

import flare.jayutils as c_jayutils
import flare.argtracker as c_argtracker

#c_jayutils.configLogger('', logging.DEBUG)
c_jayutils.configLogger('', logging.INFO)
logger = c_jayutils.getLogger('')



def getFunctionArgumentCount(ea):
    '''
    Bit of a hack, since IDA doesn't seem to have a good way to get this information.
    Gets the frame for a given function, and counts named members following the 'r'
    member.
    Note: IDA won't create a frame member for an unreferenced function arg... so you've
    been warned.
    '''
    rFound = False
    argCount = 0
    sid = idc.GetFrame(ea)
    midx = idc.GetFirstMember(sid)
    while midx != idc.BADADDR:
        name = idc.GetMemberName(sid, midx)
        if rFound and name is not None:
            argCount += 1 
            #print 'Found arg at 0x%x: "%s"' % (midx, name)
        elif name  == ' r':
            #print 'Found r at 0x%x:' % midx
            rFound = True
        else:
            #print 'Found nonarg at 0x%x: "%s"' % (midx, name)
            pass
        midx = idc.GetStrucNextOff(sid, midx)
    return argCount

def handleCreateThread(ea):
    logger.debug('handleCreateThread: starting up 0x%08x', ea)
    vw = c_jayutils.loadWorkspace(c_jayutils.getInputFilepath())
    logger.info('Loaded workspace')
    tracker = c_argtracker.ArgTracker(vw)
    interestingXrefs = idautils.CodeRefsTo(ea, 1)

    for xref in interestingXrefs:
        argsList = tracker.getPushArgs(xref, 7)
        if len(argsList) == 0:
            logger.error('Unable to get push args at: 0x%08x', xref)
        else:
            for argDict in argsList:
                loadVa, funcVa = argDict[3]
                print 'Found: 0x%08x: 0x%08x' % (loadVa, funcVa)

def main():
    beginThreadExLoc = idc.LocByName('_beginthreadex')
    if beginThreadExLoc == idc.BADADDR:
        print 'Function "_beginthreadex" not found. Returning'
        return
    for xref in idautils.CodeRefsTo(beginThreadExLoc, 1):
        if getFunctionArgumentCount(xref) == 7:
            print 'Found likely MyCreateThread: 0x%08x' % xref
            handleCreateThread(idc.GetFunctionAttr(xref, idc.FUNCATTR_START))

main()
