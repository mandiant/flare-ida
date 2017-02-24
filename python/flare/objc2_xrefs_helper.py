############################################
##Author: James T. Bennett
##Objective-C xrefs helper IDApython script
############################################

########################################################################
# Copyright 2017 FireEye
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

from idc import *
from idaapi import *
from idautils import *

size_DWORD = 4
size_pointer = 8

objcData = None
objcSelRefs = None
objcMsgRefs = None
objcConst = None
objc2ClassSize = 0x28
objc2ClassInfoOffs = 0x20
objc2ClassMethSize = 0x18
objc2ClassBaseMethsOffs = 0x20
objc2ClassMethImpOffs = 0x10


# checks that methname has an xref to selrefs or the msgrefs section, returns ref pointer
# checks if methname is used in more than one class, avoid dealing with these ambiguous cases
def getRefPtr(classMethodsVA):
    global objcSelRefs, objcMsgRefs, objcConst
    ret = (None, None)
    namePtr = Qword(classMethodsVA)
    cnt = 0
    for x in XrefsTo(namePtr):
        if objcSelRefs and x.frm >= objcSelRefs[0] and x.frm < objcSelRefs[1]:
            ret = (False, x.frm)
        elif objcMsgRefs and x.frm >= objcMsgRefs[0] and x.frm < objcMsgRefs[1]:
            ret = (True, x.frm)
        elif x.frm >= objcConst[0] and x.frm < objcConst[1]:
            cnt += 1    
        
    if cnt > 1:
        ret = (None, None)
    return ret


def main():
    # iterate segments, grab the VAs we need
    for segVA in Segments():
        segName = SegName(segVA)
        if segName == "__objc_data":
            objcData = (segVA, SegEnd(segVA))
        elif segName == "__objc_selrefs":
            objcSelRefs = (segVA, SegEnd(segVA))
        elif segName == "__objc_msgrefs":
            objcMsgRefs = (segVA, SegEnd(segVA))
        elif segName == "__objc_const":
            objcConst = (segVA, SegEnd(segVA))
      
    if not ((objcSelRefs or objcMsgRefs) and objcData and objcConst):
        Message("could not find necessary Objective-C sections..\n")
        return
        
    # walk classes
    for va in range(objcData[0], objcData[1], objc2ClassSize):
        classRoVA = Qword(va + objc2ClassInfoOffs)
        if classRoVA == idc.BADADDR or classRoVA == 0:
            continue
            
        classMethodsVA = Qword(classRoVA + objc2ClassBaseMethsOffs)
        
        if classMethodsVA == idc.BADADDR or classMethodsVA == 0:
            continue
        
        count = Dword(classMethodsVA + size_DWORD)
        classMethodsVA += size_DWORD * 2 # advance to start of class methods array
        
        # walk methods
        for va2 in range(classMethodsVA, classMethodsVA + objc2ClassMethSize * count, objc2ClassMethSize):
            isMsgRef, selRefVA = getRefPtr(va2)
            if selRefVA == None:
                continue
            
            funcVA = Qword(va2 + objc2ClassMethImpOffs)
                      
            # adjust pointer to beginning of message_ref struct to get xrefs
            if isMsgRef:
                selRefVA -= size_pointer
                
            Message("selref VA: %08X - function VA: %08X\n" % (selRefVA, funcVA))
            # add xref to func and change instruction to point to function instead of selref
            for x in XrefsTo(selRefVA):
                if GetMnem(x.frm) == "call":
                    continue
                add_dref(x.frm, funcVA, dr_I | XREF_USER)
                # 7 is size of instruction
                offs = funcVA - x.frm - 7
                PatchDword(x.frm + 3, offs)

if __name__ == '__main__':
    main()