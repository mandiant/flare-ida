############################################
# Copyright (C) 2018 FireEye, Inc.
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-BSD-3-CLAUSE or
# https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#
# Author: James T. Bennett
#
# objc2_analyzer uses emulation to perform analysis of Objective-C code in a Mach-O
#
# Currently supports Objective-C 2.0 for x86_64, ARM, and ARM64
# selRefs are changed to point to implementation of method where applicable.
# xrefs are added from msgSend calls to the implementation where applicable.
# Helpful Objective-C syntax comments are added to each msgSend call
# Does not track id/sel pointers across function boundaries.
# Helps IDA where it failed to track msgSend function pointers across registers.
# Tracks ivar types throughout a function
#
# Dependencies:
# https://github.com/fireeye/flare-emu
############################################

from __future__ import print_function
import idc
import idaapi
import idautils
import unicorn
import unicorn.x86_const
import unicorn.arm_const
import unicorn.arm64_const
import logging
import struct
import flare_emu
import re

UNKNOWN = "??"
MAX_STR_DISPLAY_LEN = 20

class Objc2Analyzer():
    def __init__(self):
        self.magicMask64 = 0xabbadabbad000000
        self.magicMask32 = 0xabba0000
        self.magicMaskMask64 = 0xffffffffffff0000
        self.magicMaskMask32 = 0xffff0000
        self.callMnems = ["call", "jmp", "BL", "BLX", "BLEQ", "BLXEQ", "BLR", "BLREQ", "B"]
        self.objcData = None
        self.objcSelRefs = None
        self.objcMsgRefs = None
        self.objcConst = None
        self.objcClassRefs = None
        self.objcCatList = None
        self.fixedSelXRefs = []
        self.ivarSetters = {}
        self.notIvarSetters = []
        for segVA in idautils.Segments():
            segName = idc.get_segm_name(segVA)
            endVA = idc.get_segm_end(segVA)
            if segName == "__objc_data":
                self.objcData = (segVA, endVA)
            elif segName == "__objc_selrefs":
                self.objcSelRefs = (segVA, endVA)
            elif segName == "__objc_msgrefs":
                self.objcMsgRefs = (segVA, endVA)
            elif segName == "__objc_const":
                self.objcConst = (segVA, endVA)
            elif segName == "__objc_classrefs":
                self.objcClassRefs = (segVA, endVA)
            elif segName == "__objc_catlist":
                self.objcCatList = (segVA, endVA)
        if self.objcSelRefs or self.objcMsgRefs:
            self.processObjc()
        else:
            logging.debug("this Mach-O does not implement any Objective-C classes")
    
    # it appears idc.get_name_ea_simple does not work for selector reference names that end in "_"
    def selRefLocByName(self, name):
        if name[:6] == "selRef":
            addr = self.objcSelRefs[0]
            endAddr = self.objcSelRefs[1]
        else:
            addr = self.objcMsgRefs[0]
            endAddr = self.objcMsgRefs[1]
        while addr < endAddr:
            if idc.get_name(addr, idc.ida_name.GN_VISIBLE) == name:
                return addr
            addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))


    def objc2AnalyzeHookX64(self, uc, address, size, userData):
        try:
            eh = userData["EmuHelper"]
            # move ivar ptr into reg instead of value of ivar, so we can check for ivar refs coming up in the code
            if idc.print_insn_mnem(address) == "mov" and idc.get_operand_type(address, 1) == 2:
                opval = idc.get_operand_value(address, 1)
                srcOpName = idc.get_name(opval, idc.ida_name.GN_VISIBLE)
                if srcOpName[:13] == "_OBJC_IVAR_$_":
                    logging.debug("IVAR reference found for %s, storing %s" %
                                  (srcOpName, eh.hexString(opval)))
                    uc.reg_write(eh.regs[idc.print_operand(address, 0)], opval)
                    eh.skipInstruction(userData)
                    return
            # look for mov instruction with [reg + reg] and check each reg for pointing to ivar, store ivar info in dst
            # operand
            if (idc.print_insn_mnem(address) == "mov" and
                    idc.get_operand_type(address, 0) == 1 and
                    idc.get_operand_type(address, 1) in [3, 4]):
                dstopnd = idc.print_operand(address, 0)
                srcopnd = idc.print_operand(address, 1)
                regs = srcopnd[1:-1]
                if (dstopnd[0] == "r" and
                        ((len(regs) == 7 and regs[3:5] == "+r") or
                         (len(regs) == 9 and regs[3] == "+" and regs[7:] == "+0"))):
                    regs = regs.split("+")
                    reg1 = None
                    reg2 = None
                    if regs[0] in eh.regs:
                        reg1 = eh.getRegVal(regs[0])
                    if regs[1] in eh.regs:
                        reg2 = eh.getRegVal(regs[1])
                    logging.debug("possible IVAR reference found @%s, reg1: %s reg2: %s" % (
                        eh.hexString(address), eh.hexString(reg1), eh.hexString(reg2)))
                    if type(reg1) is long and idc.get_name(reg1, idc.ida_name.GN_VISIBLE)[:13] == "_OBJC_IVAR_$_":
                        uc.reg_write(eh.regs[dstopnd], self.getIvarInfo(eh, reg1, userData))
                        eh.skipInstruction(userData)
                        return
                    elif type(reg2) is long and idc.get_name(reg2, idc.ida_name.GN_VISIBLE)[:13] == "_OBJC_IVAR_$_":
                        uc.reg_write(eh.regs[dstopnd], self.getIvarInfo(eh, reg2, userData))
                        eh.skipInstruction(userData)
                        return

            # track selector xrefs
            srcOpName = idc.get_name(idc.get_operand_value(address, 1), idc.ida_name.GN_VISIBLE)
            sel = None
            if idc.print_insn_mnem(address) == "mov" and srcOpName[:7] == "selRef_":
                sel = eh.getEmuPtr(idc.get_operand_value(address, 1))
            elif idc.print_insn_mnem(address) == "lea" and srcOpName[:7] == "msgRef_":
                sel = idc.get_operand_value(address, 1)
            if sel:
                userData["magicVals"].append((address, sel))
                mv = self.magicMask64 | userData["magicValsCount"]
                userData["magicValsCount"] += 1
                uc.reg_write(eh.regs[idc.print_operand(address, 0)], mv)
                logging.debug("writing magic value %s to %s for %s @%s" % (eh.hexString(
                    mv), idc.print_operand(address, 0), srcOpName, eh.hexString(address)))
                eh.skipInstruction(userData)
                return

        except Exception as e:
            logging.debug("exception in objc2AnalyzeHookX64 @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            print("exception in objc2AnalyzeHookX64 @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            eh.stopEmulation(userData)


    def objc2AnalyzeHookARM(self, uc, address, size, userData):
        try:
            eh = userData["EmuHelper"]
            opCnt = 0
            while idc.get_operand_type(address, opCnt) != 0:
                opCnt += 1

            # LDR commands may be used for getting ptr to IVARs or selector references
            if idc.print_insn_mnem(address)[:3] == "LDR":
                opnd = idc.print_operand(address, 1)
                if len(opnd) < 6 and opnd[0] == "[":
                    m = re.match(r"\[([^\,\]]+)\]", opnd)
                    if m:
                        opreg = m.group(1)
                        opval = eh.getRegVal(opreg)
                        if opval & self.magicMaskMask32 == self.magicMask32:
                            logging.debug("magic value found in %s @%s, storing %s" % (
                                opreg, eh.hexString(address), eh.hexString(opval)))
                            uc.reg_write(
                                eh.regs[idc.print_operand(address, 0)], opval)
                            eh.skipInstruction(userData, True)
                            return
                # LDR to get ivar address, just store magic val
                if idc.get_operand_type(address, 1) == 3:
                    m = re.match(r"\[([^\,\]]+),([^\,\]]+)\]", opnd)
                    if m:
                        dstopnd = idc.print_operand(address, 0)
                        mv = None
                        for i in range(1, 3):
                            if m.group(i) in eh.regs:
                                regVal = eh.getRegVal(m.group(i))
                                if type(regVal) is long and regVal & self.magicMaskMask32 == self.magicMask32:
                                    # if both regs contain magic val, choose the ivar val over the self val
                                    if mv is None or (len(userData["magicVals"][regVal & 0xFFFF]) == 2 and
                                                      ")self" not in userData["magicVals"][regVal & 0xFFFF][0]):
                                        mv = regVal
                        if mv:
                            uc.reg_write(eh.regs[dstopnd], mv)
                            eh.skipInstruction(userData, True)
                            return
            # MOV instructions may be moving sel/msg refs or ivars
            elif idc.print_insn_mnem(address)[:3] == "MOV" and idc.print_operand(address, 1)[0] == "#":
                srcOpnd = idc.print_operand(address, 1)
                dstOpnd = idc.print_operand(address, 0)
                sel = None
                if srcOpnd[:9] == "#(selRef_":
                    srcOpName = srcOpnd[2:srcOpnd.find(" ")]
                    sel = eh.getEmuPtr(self.selRefLocByName(srcOpName))
                elif srcOpnd[:9] == "#(msgRef_":
                    srcOpName = srcOpnd[2:srcOpnd.find(" ")]
                    sel = self.selRefLocByName(srcOpName)
                elif srcOpnd[:18] == "#:upper16:(selRef_":
                    # just skip the upper MOVs, we handle the lower MOVs
                    eh.skipInstruction(userData, True)
                    return
                elif srcOpnd[:18] == "#:lower16:(selRef_":
                    srcOpName = srcOpnd[11:srcOpnd.find(" ")]
                    sel = eh.getEmuPtr(self.selRefLocByName(srcOpName))
                elif srcOpnd[:18] == "#:upper16:(msgRef_":
                    # just skip the upper MOVs, we handle the lower MOVs
                    eh.skipInstruction(userData, True)
                    return
                elif srcOpnd[:18] == "#:lower16:(msgRef_":
                    srcOpName = srcOpnd[11:srcOpnd.find(" ")]
                    sel = self.selRefLocByName(srcOpName)
                elif srcOpnd[:15] == "#(_OBJC_IVAR_$_":
                    ivarVa = idc.get_name_ea_simple(
                        srcOpnd[srcOpnd.find("_OBJC_IVAR_$_"):srcOpnd.find(" ")])
                    mv = self.getIvarInfo(eh, ivarVa, userData)
                    logging.debug("IVAR reference found @%s, storing magic value %s in %s" % (
                        eh.hexString(address), eh.hexString(mv), dstOpnd))
                    uc.reg_write(eh.regs[dstOpnd], mv)
                    eh.skipInstruction(userData, True)
                    return
                elif srcOpnd[:24] == "#:lower16:(_OBJC_IVAR_$_":
                    ivarVa = idc.get_name_ea_simple(
                        srcOpnd[srcOpnd.find("_OBJC_IVAR_$_"):srcOpnd.find(" ")])
                    mv = self.getIvarInfo(eh, ivarVa, userData)
                    logging.debug("IVAR reference found @%s, storing magic value %s in %s" % (
                        eh.hexString(address), eh.hexString(mv), dstOpnd))
                    uc.reg_write(eh.regs[dstOpnd], mv)
                    eh.skipInstruction(userData, True)
                    return
                elif srcOpnd[:24] == "#:upper16:(_OBJC_IVAR_$_":
                    # just skip the upper MOVs, we handle the lower MOVs
                    eh.skipInstruction(userData, True)
                    return

                # track sel xrefs
                if sel:
                    userData["magicVals"].append((address, sel))
                    mv = self.magicMask32 | userData["magicValsCount"]
                    userData["magicValsCount"] += 1
                    uc.reg_write(eh.regs[dstOpnd], mv)
                    logging.debug("writing magic value %s to %s for %s @%s" % (
                        eh.hexString(mv), dstOpnd, srcOpName, eh.hexString(address)))
                    eh.skipInstruction(userData, True)
                    return
            # skip the ADD instructions with two operands for selrefs and magic vals
            elif (idc.print_insn_mnem(address)[:3] == "ADD" and opCnt == 2 and
                    (idc.get_name(eh.getRegVal(idc.print_operand(address, 0)), 
                    idc.ida_name.GN_VISIBLE)[:7] == "selRef_" or 
                    eh.getRegVal(idc.print_operand(address, 0)) & self.magicMaskMask32 == 
                    self.magicMask32)):
                    
                # if the 2nd operand is an ivar magic val overwrite the 1st reg with it
                if idc.get_operand_type(address, 1) == 1:
                    regVal = eh.getRegVal(idc.print_operand(address, 1))
                    if (type(regVal) is long and regVal & self.magicMaskMask32 == self.magicMask32 and 
                            (len(userData["magicVals"][regVal & 0xFFFF]) == 2 and
                             type(userData["magicVals"][regVal & 0xFFFF][0]) is str and
                             ")self" not in userData["magicVals"][regVal & 0xFFFF][0] and
                             userData["magicVals"][regVal & 0xFFFF][0][0] != "[")):
                                uc.reg_write(eh.regs[idc.print_operand(address, 0)], regVal)
                eh.skipInstruction(userData, True)
                return
            # look for ADD instructions that are adding registers and check each reg for pointing to magic val, store
            # magic val in dst operand
            elif (idc.print_insn_mnem(address)[:3] == "ADD" and idc.get_operand_type(address, 0) == 1 and
                  idc.get_operand_type(address, 1) == 1):
                dstOpnd = idc.print_operand(address, 0)
                i = 1
                mv = None
                while idc.get_operand_type(address, i) != 0:
                    if idc.get_operand_type(address, i) == 1:
                        reg = idc.print_operand(address, i)
                        if reg in eh.regs:
                            regVal = eh.getRegVal(reg)
                            if type(regVal) is long and regVal & self.magicMaskMask32 == self.magicMask32:
                                # favor the ivar over the returned id or self id
                                if mv is None or (len(userData["magicVals"][regVal & 0xFFFF]) == 2 and
                                                  type(userData["magicVals"][regVal & 0xFFFF][0]) is str and
                                                  ")self" not in userData["magicVals"][regVal & 0xFFFF][0] and
                                                  userData["magicVals"][regVal & 0xFFFF][0][0] != "["):
                                    mv = regVal
                    i += 1

                if mv:
                    uc.reg_write(eh.regs[dstOpnd], mv)
                    eh.skipInstruction(userData)
                    return

        except Exception as e:
            logging.debug("exception in objc2AnalyzeHookARM @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            print("exception in objc2AnalyzeHookARM @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            eh.stopEmulation(userData)


    def objc2AnalyzeHookARM64(self, uc, address, size, userData):
        try:
            eh = userData["EmuHelper"]
            opCnt = 0
            while idc.get_operand_type(address, opCnt) != 0:
                opCnt += 1

            # LDR instructions may be used for getting ptr to IVARs or selector references in 
            # Link Time Optimized Mach-Os
            # LDRSW           X8, =8  ; NSString *_myVar;
            #
            # LDR             X20, =sel_new
            if idc.print_insn_mnem(address)[:3] == "LDR":
                srcOpnd = idc.print_operand(address, 1)
                dstOpnd = idc.print_operand(address, 0)
                # dereferencing PC offset
                if srcOpnd[0] == "=":
                    for x in idautils.XrefsFrom(address):
                        if (idc.get_segm_name(x.to) == "__objc_ivar" and
                                idc.get_name(x.to, idc.ida_name.GN_VISIBLE)[:13] == "_OBJC_IVAR_$_"):
                            srcOpName = idc.get_name(x.to, idc.ida_name.GN_VISIBLE)
                            mv = self.getIvarInfo(eh, x.to, userData)
                            logging.debug("IVAR reference found @%s for %s, storing magic value %s in %s" % (
                                eh.hexString(address), srcOpName, eh.hexString(mv), dstOpnd))
                            uc.reg_write(eh.regs[dstOpnd], mv)
                            eh.skipInstruction(userData)
                            return
                        # Link Time Optimized Mach-Os will use LDR and IDA will xref to sel itself
                        elif (idc.get_segm_name(x.to) == "__objc_methname" and
                              idc.get_name(x.to, idc.ida_name.GN_VISIBLE)[:4] == "sel_"):
                            # track sel xrefs
                            selName = idc.get_name(x.to, idc.ida_name.GN_VISIBLE)
                            sel = x.to
                            userData["magicVals"].append((address, sel))
                            mv = self.magicMask64 | userData["magicValsCount"]
                            userData["magicValsCount"] += 1
                            uc.reg_write(eh.regs[dstOpnd], mv)
                            logging.debug("writing magic value %s to %s for %s @%s" % (
                                eh.hexString(mv), dstOpnd, selName, eh.hexString(address)))
                            eh.skipInstruction(userData)
                            return
                            
                # accessing Ivar offset in class object or classref/selref offset from ADRP page base
                # LDR instruction to get IVAR offset from id pointer
                # LDRSW           X8, =8  ; NSString *_myVar;
                # LDR             X0, [X0,X8]
                # 
                # ADRP            X25, #classRef_SimpleClass@PAGE
                # LDR             X0, [X25,#classRef_SimpleClass@PAGEOFF]
                elif idc.get_operand_type(address, 1) == 3:
                    m = re.match(r"\[([^\,\]]+)\,([^\,\]]+)\]", srcOpnd)
                    if m:
                        mv = None
                        for i in range(1, 3):
                            if m.group(i)[:8] == "#selRef_":
                                selref = self.selRefLocByName(
                                    m.group(i)[1:m.group(i).find("@")])
                                sel = eh.getEmuPtr(selref)
                                userData["magicVals"].append((address, sel))
                                mv = self.magicMask64 | userData["magicValsCount"]
                                userData["magicValsCount"] += 1
                                uc.reg_write(eh.regs[dstOpnd], mv)
                                logging.debug("writing magic value %s to %s for %s @%s" % (
                                    eh.hexString(mv), dstOpnd, m.group(i)[1:], eh.hexString(address)))
                                eh.skipInstruction(userData)
                                return
                            elif m.group(i)[:10] == "#classRef_":
                                clsRef = m.group(i)[1:m.group(i).find("@")]
                                id = eh.getEmuPtr(idc.get_name_ea_simple(clsRef))
                                userData["magicVals"].append((id, ""))
                                mv = self.magicMask64 | userData["magicValsCount"]
                                userData["magicValsCount"] += 1
                                uc.reg_write(eh.regs[dstOpnd], mv)
                                logging.debug("writing magic value %s to %s for %s @%s" % (
                                    eh.hexString(mv), dstOpnd, m.group(i)[1:], eh.hexString(address)))
                                eh.skipInstruction(userData)
                                return
                            elif m.group(i) in eh.regs:
                                regVal = eh.getRegVal(m.group(i))
                                if type(regVal) is long and regVal & self.magicMaskMask64 == self.magicMask64:
                                    if mv is None or (len(userData["magicVals"][regVal & 0xFFFF]) == 2 and
                                                      type(userData["magicVals"][regVal & 0xFFFF][0]) is str and
                                                      ")self" not in userData["magicVals"][regVal & 0xFFFF][0]):
                                        mv = regVal

                        if mv:
                            uc.reg_write(eh.regs[dstOpnd], mv)
                            eh.skipInstruction(userData)
                            return
                # LDR instruction to retrieve sel/ivar when not Link Time Optimized
                # LDR             X1, [X1] ; "new"
                elif idc.get_operand_type(address, 1) == 4:
                    if srcOpnd[1:-1] in eh.regs:
                     regVal = eh.getRegVal(srcOpnd[1:-1])
                     if type(regVal) is long and regVal & self.magicMaskMask64 == self.magicMask64:
                        uc.reg_write(eh.regs[dstOpnd], regVal)
                        eh.skipInstruction(userData)
                        return
            # Non Link Time Optimized Mach-O uses ADRP/ADD to retrieve sels/ivars            
            # ADRP            X1, #selRef_new@PAGE
            # ADD             X1, X1, #selRef_new@PAGEOFF
            elif idc.print_insn_mnem(address) == "ADRP":
                srcOpnd = idc.print_operand(address, 1)
                dstOpnd = idc.print_operand(address, 0)
                if srcOpnd[0] == "#":
                    for x in idautils.XrefsFrom(address):
                        if (idc.get_segm_name(x.to) == "__objc_ivar" and
                                idc.get_name(x.to, idc.ida_name.GN_VISIBLE)[:13] == "_OBJC_IVAR_$_"):
                            srcOpName = idc.get_name(x.to, idc.ida_name.GN_VISIBLE)
                            mv = self.getIvarInfo(eh, x.to, userData)
                            logging.debug("IVAR reference found @%s for %s, storing magic value %s in %s" % (
                                eh.hexString(address), srcOpName, eh.hexString(mv), dstOpnd))
                            uc.reg_write(eh.regs[dstOpnd], mv)
                            eh.skipInstruction(userData)
                            return
                        elif (idc.get_segm_name(x.to) == "__objc_selrefs" and
                              idc.get_name(x.to, idc.ida_name.GN_VISIBLE)[:7] == "selRef_"):
                              # track sel xrefs
                            sel = eh.derefPtr(x.to)
                            selName = idc.get_name(sel, idc.ida_name.GN_VISIBLE)
                            userData["magicVals"].append((address, sel))
                            mv = self.magicMask64 | userData["magicValsCount"]
                            userData["magicValsCount"] += 1
                            uc.reg_write(eh.regs[dstOpnd], mv)
                            logging.debug("writing magic value %s to %s for %s @%s" % (
                                eh.hexString(mv), dstOpnd, selName, eh.hexString(address)))
                            # skip two instructions to skip succeeding ADD
                            uc.reg_write(eh.regs["pc"], userData["currAddr"] + 8)
                            return
                        
                return
                    
            # skip the ADD instructions with two operands for our magic values
            elif (idc.print_insn_mnem(address)[:3] == "ADD" and
                    opCnt == 2 and
                    eh.getRegVal(idc.print_operand(address, 0)) & self.magicMaskMask64 == self.magicMask64):
                eh.skipInstruction(userData)
                return
            # look for ADD instructions that are adding registers and check each reg for pointing to magic val, store
            # magic val in dst operand
            elif (idc.print_insn_mnem(address)[:3] == "ADD" and
                  idc.get_operand_type(address, 0) == 1 and
                  idc.get_operand_type(address, 1) == 1):
                dstopnd = idc.print_operand(address, 0)
                i = 1
                mv = None
                while idc.get_operand_type(address, i) != 0:
                    if idc.get_operand_type(address, i) in [1, 8]:
                        reg = idc.print_operand(address, i)
                        if reg in eh.regs:
                            regVal = eh.getRegVal(reg)
                            if type(regVal) is long and regVal & self.magicMaskMask64 == self.magicMask64:
                                # favor the ivar over the returned id or self id
                                if mv is None or (len(userData["magicVals"][regVal & 0xFFFF]) == 2 and
                                                  type(userData["magicVals"][regVal & 0xFFFF][0]) is str and
                                                  ")self" not in userData["magicVals"][regVal & 0xFFFF][0] and
                                                  userData["magicVals"][regVal & 0xFFFF][0][0] != "["):
                                    mv = regVal
                    i += 1

                if mv:
                    uc.reg_write(eh.regs[dstopnd], mv)
                    eh.skipInstruction(userData)
                    return

        except Exception as e:
            logging.debug("exception in objc2AnalyzeHookARM64 @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            print("exception in objc2AnalyzeHookARM64 @%s: (%s) %s" % (eh.hexString(address), type(e), e))
            eh.stopEmulation(userData)


    # used to work backwards and get selref from imp ptr in cases where patch has already been applied
    def getSelRefFromImpPtr(self, eh, imp):
        selref = None
        retClsName = ""
        if eh.arch == unicorn.UC_ARCH_ARM and eh.isThumbMode(imp):
            imp |= 1
        logging.debug("checking xrefs for IMP %s" % eh.hexString(imp))
        for x in idautils.XrefsTo(imp):
            if x.frm >= self.objcConst[0] and x.frm < self.objcConst[1]:
                # even though imp ptr is stored at offset 0x10 in struct, xref just goes to base of struct, we want the
                # first field
                for y in idautils.XrefsTo(eh.derefPtr(x.frm)):
                    if y.frm >= self.objcSelRefs[0] and y.frm < self.objcSelRefs[1]:
                        selref = y.frm
                        break
                # determine return value's type
                # check type string to see if id is returned
                typeStr = eh.getIDBString(eh.derefPtr(x.frm + eh.size_pointer))
                if len(typeStr) > 0 and typeStr[0] == "@":
                    # scan imp for ivar reference, grab its type
                    if eh.arch == unicorn.UC_ARCH_ARM and eh.isThumbMode(imp):
                        imp = imp & ~1
                    retClsName = self.getIvarTypeFromFunc(eh, imp)

        return selref, retClsName


    def callHook(self, address, argv, funcName, userData):
        eh = userData["EmuHelper"]
        if eh.size_pointer == 4:
            magicMask = self.magicMask32
            magicMaskMask = self.magicMaskMask32
        else:
            magicMask = self.magicMask64
            magicMaskMask = self.magicMaskMask64

        if "retainAutorelease" in funcName or "_objc_retain" in funcName:
            eh.uc.reg_write(eh.regs["ret"], argv[0])
        elif "_objc_store" in funcName:
            eh.uc.reg_write(eh.regs["ret"], argv[1])
            if eh.isValidEmuPtr(argv[0]):
                eh.writeEmuPtr(argv[0], argv[1])
        # ARM instruction patched to BLX to get xref, get selref
        elif ((eh.arch == unicorn.UC_ARCH_ARM or eh.arch == unicorn.UC_ARCH_ARM64) and
                address in userData["patchedSelRefs"]):
            selref, retClsName = self.getSelRefFromImpPtr(
                eh, idc.get_func_attr(idc.get_operand_value(address, 0), idc.FUNCATTR_START))
            logging.debug("ARM: got selref %s from imp ptr %s @%s" % (eh.hexString(selref), eh.hexString(
                idc.get_func_attr(idc.get_operand_value(address, 0), idc.FUNCATTR_START)), eh.hexString(address)))
            # grab register name
            reg, skip = userData["patchedSelRefs"][address]
            if eh.arch == unicorn.UC_ARCH_ARM64:
                sel = eh.derefPtr(selref)
                eh.uc.reg_write(eh.regs[reg], sel)
                logging.debug("set %s to sel %s" % (reg, eh.hexString(sel)))
            else:
                eh.uc.reg_write(eh.regs[reg], selref)
                logging.debug("set %s to selref %s" % (reg, eh.hexString(selref)))
            # skip bytes to next instruction (emulator memory is not the same as IDB)
            logging.debug("skipping %d bytes" % skip)
            eh.changeProgramCounter(userData, address + skip)
            return
        elif "msgSend" in funcName:
            retClsName = ""
            selXref = None
            # get sel and id
            if "_stret" in funcName:
                sel = argv[2]
            else:
                sel = argv[1]
            if sel & magicMaskMask == magicMask:
                selXref, sel = userData["magicVals"][sel & 0xffff]
                logging.debug("found magic sel used @%s: %s" %
                              (eh.hexString(address), eh.hexString(sel)))
            selName = idc.get_name(sel, idc.ida_name.GN_VISIBLE)
            # if dealing with a msgref, we dont need to get xref
            selref = None
            logging.debug("selName = %s" % selName)
            if selName[:7] == "msgRef_":
                selref = sel
            elif selName[:4] == "sel_":
                for x in idautils.XrefsTo(sel):
                    if x.frm >= self.objcSelRefs[0] and x.frm < self.objcSelRefs[1]:
                        selref = x.frm
                        break
            else:
                # check if selref has already been converted to imp
                if sel in list(idautils.Functions()):
                    selref, retClsName = self.getSelRefFromImpPtr(eh, sel)

            if selref:
                selName = self.formatName(idc.get_name(selref, idc.ida_name.GN_VISIBLE))
                # get id info
                isInstance = True
                if "_stret" in funcName:
                    id = argv[1]
                else:
                    id = argv[0]
                if "Super" in funcName:
                    id = eh.getEmuPtr(id)
                if idc.get_segm_name(id) == "__objc_methtype":
                    id = clsName = eh.getIDBString(id)[2:-1]
                elif id & magicMaskMask == magicMask:
                    logging.debug("magic val found for id: %s" % eh.hexString(id))
                    id, clsName = userData["magicVals"][id & 0xffff]
                else:
                    idref = None
                    nameId = idc.get_name(id, idc.ida_name.GN_VISIBLE)
                    if nameId[:6] == "cfstr_":
                        # use the first n chars of the string as the id
                        nstr = idc.get_strlit_contents(eh.derefPtr(
                            id + eh.size_pointer * 2), -1, idc.STRTYPE_C)[:MAX_STR_DISPLAY_LEN].replace("\r", "").replace("\n", "")
                        id = "@\"" + nstr
                        clsName = "NSString"
                        if len(nstr) == MAX_STR_DISPLAY_LEN:
                            id += "..\""
                        else:
                            id += "\""
                    elif nameId[:14] == "_OBJC_CLASS_$_" or nameId[:15] == "_OBJC_CATEGORY_":
                        id = clsName = self.formatName(nameId)
                        isInstance = False
                    elif nameId == "_NSApp":
                        id = clsName = "NSApp"
                    else:
                        for x in idautils.XrefsTo(id):
                            if idc.get_name(x.frm, idc.ida_name.GN_VISIBLE)[:9] == "classRef_":
                                idref = x.frm
                                break
                        if idref is None:
                            id = clsName = UNKNOWN
                        else:
                            id = clsName = self.formatName(idc.get_name(idref, idc.ida_name.GN_VISIBLE))
                            isInstance = False
                if selName == "init" or selName == "new" or selName == "sharedInstance":
                    retClsName = clsName
                elif selName == "class":
                    retClsName = clsName + "_&_class"
                elif selName == "alloc":
                    retClsName = clsName + "_&_alloc"

                if clsName == "":
                    clsName = UNKNOWN
                elif clsName[-8:] == "_&_alloc":
                    clsName = clsName[:-8]
                    retClsName = clsName
                elif clsName[-8:] == "_&_class":
                    clsName = clsName[:-8]
                    isInstance = False

                # determine return value type
                if retClsName == "" and clsName in userData["classes"]:
                    if isInstance:
                        type_ = "instance"
                    else:
                        type_ = "class"
                    # get IMP for selref
                    funcVA = None
                    logging.debug("determining return value type")
                    for x in userData["classes"][clsName][type_]:
                        if x[0] == selref:
                            funcVA = x[1]
                            break
                    # find method struct for IMP and get type info
                    if funcVA:
                        logging.debug("IMP ptr: %s" % eh.hexString(funcVA))
                        tgt = funcVA
                        if eh.arch == unicorn.UC_ARCH_ARM:
                            tgt = funcVA | 1
                        for x in idautils.XrefsTo(tgt):
                            if x.frm >= self.objcConst[0] and x.frm < self.objcConst[1]:
                                # check type string to see if id is returned
                                typeStr = eh.getIDBString(
                                    eh.derefPtr(x.frm + eh.size_pointer))
                                logging.debug("type string: %s" % typeStr)
                                if len(typeStr) > 0 and typeStr[0] == "@":
                                    # scan imp for ivar reference, grab its type
                                    retClsName = self.getIvarTypeFromFunc(eh, funcVA)
                                    logging.debug("ret cls name: %s" % retClsName)
                                break

                # save objc syntax of call to reference later if used elsewhere
                userData["magicVals"].append(
                    ("[%s %s]" % (id, selName), retClsName))
                eh.uc.reg_write(eh.regs["ret"], magicMask |
                             userData["magicValsCount"])
                userData["magicValsCount"] += 1
                # if IDA didn't know about this xref to msgSend and we didn't catch it with our wider net, process it now
                if (address not in userData["msgSendXrefs"] and address not in userData["possibleMsgSendXrefs"] and
                        idc.get_operand_type(address, 0) == 1):
                    self.processMsgSend(eh, address, id, selName, clsName,
                                   isInstance, selref, selXref, userData)
                    idc.add_dref(address, eh.getRegVal(idc.print_operand(address, 0)), idc.dr_I | idc.XREF_USER)
                    logging.debug("found undiscovered msgSend xref@%s" %
                                  eh.hexString(address))
                    userData["msgSendXrefs"].append(address)
            else:
                logging.debug("couldn't find sel (%s) for msgSend call @%s" %
                              (eh.hexString(sel), eh.hexString(address)))
                if address in userData["targetInfo"] and address not in userData["visitedTargets"]:
                    userData["visitedTargets"].append(address)
                idc.set_cmt(address, "objc2_analyzer failed to determine arguments", 0)
                return

            # this call is one of those "call reg" instructions we thought might be a msgSend call, but wasn't sure
            if (address in userData["possibleMsgSendXrefs"] and idc.get_operand_type(address, 0) == 1 and "msgSend" in
                    idc.get_name(eh.getRegVal(idc.print_operand(address, 0)), idc.ida_name.GN_VISIBLE)):
                self.processMsgSend(eh, address, id, selName, clsName,
                               isInstance, selref, selXref, userData)
                idc.add_dref(address, eh.getRegVal(idc.print_operand(address, 0)), idc.dr_I | idc.XREF_USER)
                logging.debug("found undiscovered msgSend xref@%s" %
                              eh.hexString(address))
            elif address in userData["msgSendXrefs"]:
                self.processMsgSend(eh, address, id, selName, clsName,
                               isInstance, selref, selXref, userData)


    def targetCallback(self, eh, address, argv, userData):
        # we do everything we need to do here in the callHook instead
        pass


    # uses heuristic to determine if getter function, then returns the type of the ivar
    def getIvarTypeFromFunc(self, eh, va):
        if va in self.ivarSetters:
            return self.ivarSetters[va]
        elif va in self.notIvarSetters:
            return UNKNOWN
        addr = va
        endVa = idc.get_func_attr(va, idc.FUNCATTR_END)
        if endVa - va < 0x20:
            ivarVa = None
            while addr <= endVa:
                srcOpnd = idc.print_operand(addr, 1)
                # if ivar is the src op for an instruction, assume this function will return it
                if eh.arch == unicorn.UC_ARCH_ARM and "_OBJC_IVAR_$_" in srcOpnd:
                    oploc = idc.get_name_ea_simple(
                        srcOpnd[srcOpnd.find("_OBJC_IVAR_$_"):srcOpnd.find(" ")])
                    if oploc != idc.BADADDR:
                        ivarVa = oploc
                        break
                elif eh.arch == unicorn.UC_ARCH_ARM64:
                    for x in idautils.XrefsFrom(addr):
                        if (idc.get_segm_name(x.to) == "__objc_ivar" and
                                idc.get_name(x.to, idc.ida_name.GN_VISIBLE)[:13] == "_OBJC_IVAR_$_"):
                            ivarVa = x.to
                            break
                elif eh.arch == unicorn.UC_ARCH_X86:
                    if "_OBJC_IVAR_$_" in srcOpnd:
                        ivarVa = idc.get_operand_value(addr, 1)
                        break

                addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))

            if ivarVa:
                for x in idautils.XrefsTo(ivarVa):
                    if x.frm >= self.objcConst[0] and x.frm < self.objcConst[1]:
                        typeStr = eh.getIDBString(
                            eh.derefPtr(x.frm + eh.size_pointer * 2))
                        self.ivarSetters[va] = typeStr[2:-1]
                        logging.debug("%s is an ivar getter function, returning type %s" % (
                            eh.hexString(va), typeStr[2:-1]))
                        return typeStr[2:-1]
            else:
                logging.debug(
                    "%s determined not to be an ivar getter function", eh.hexString(va))
                self.notIvarSetters.append(va)
        else:
            logging.debug(
                "%s determined not to be an ivar getter function", eh.hexString(va))
            self.notIvarSetters.append(va)
        return UNKNOWN


    # returns class or sel name from IDA name
    def formatName(self, name):
        if name[:9] == "classRef_":
            name = name[9:]
        elif name[:14] == "_OBJC_CLASS_$_":
            name = name[14:]
        elif name[:15] == "_OBJC_CATEGORY_":
            name = name[15:name.find("_$_")] + "_" + name[name.find("_$_") + 3:]
        elif name[:7] == "selRef_":
            name = name[7:]
        elif name[:7] == "msgRef_":
            name = name[7:-len("__objc_msgSend_fixup")]

        return name


    # checks that the sel ptr in the method struct has an xref to selrefs or msgrefs section, returns whether the selector
    # is ambiguous, whether it is a msgref, and the pointer to the ref
    def getRefPtr(self, eh, methodVa):
        isMsgRef, isAmbiguous, refPtr = (None, None, None)
        namePtr = eh.derefPtr(methodVa)
        cnt = 0
        for x in idautils.XrefsTo(namePtr):
            if self.objcSelRefs and x.frm >= self.objcSelRefs[0] and x.frm < self.objcSelRefs[1]:
                refPtr = x.frm
                isMsgRef = False
            elif self.objcMsgRefs and x.frm >= self.objcMsgRefs[0] and x.frm < self.objcMsgRefs[1]:
                refPtr = x.frm
                isMsgRef = True
            elif self.objcConst and x.frm >= self.objcConst[0] and x.frm < self.objcConst[1]:
                cnt += 1

        # ambiguous sel names
        isAmbiguous = False
        if cnt > 1:
            isAmbiguous = True
        return isAmbiguous, isMsgRef, refPtr


    # adds objc comment and calls fixXref to fix xrefs for objc_msgSend
    # address: address of msgSend call
    # id: class/instance name to show in comment
    # sel: selector name to show in comment
    # clsName: name of class to lookup for sel->imp mapping
    # selref: sel reference to lookup in sel->imp mapping
    def processMsgSend(self, eh, address, id, sel, clsName, isInstance, selref, selXref, userData):
        logging.debug("addr: %s id: %s sel: %s clsName: %s isInstance: %s selRef: %s selXref: %s" % (eh.hexString(0 if address == None else address), id, sel, clsName, isInstance, eh.hexString(0 if selref == None else selref), eh.hexString(0 if selXref == None else selXref)))
        if sel:
            idc.set_cmt(address, "[%s %s]" % (id, sel), 0)
        if sel and id != UNKNOWN:
            # as a convenience, if sel is "new", fix xref to "init"
            if sel == "new" and clsName in userData["classes"]:
                if (len(filter(lambda x: idc.get_name(x, idc.ida_name.GN_VISIBLE) == "selRef_init", map(lambda x: x[0],
                        userData["classes"][clsName]["instance"]))) > 0):
                    selref = filter(lambda x: idc.get_name(x, idc.ida_name.GN_VISIBLE) == "selRef_init", map(
                        lambda x: x[0], userData["classes"][clsName]["instance"]))[0]
                    isInstance = True
            if selXref and selXref not in self.fixedSelXRefs:
                self.fixXref(eh, userData["classes"], clsName, selref,
                        isInstance, selXref, address, userData)


    def assembleThumbBLXIns(self, eh, address, target):
        # pipelining and alignment
        pc = address + 4
        pc &= 0xfffffffc
        offset = (target - pc) & 0xffffffff
        logging.debug("assembling BLX instruction for offset: %08X" % offset)
        S = (offset & 0x1000000) >> 24
        I1 = (offset & 0x800000) >> 23
        I2 = (offset & 0x400000) >> 22
        # shortcut for J1 = ~I1 ^ S
        J1 = I1 ^ 1 ^ S
        J2 = I2 ^ 1 ^ S
        H = (offset & 0x3ff000) >> 12
        L = (offset & 0xffc) >> 2
        encoded = (0xf0000000 | (S << 26) | (H << 16) | (
            3 << 14) | (J1 << 13) | (J2 << 11) | (L << 1))
        encoded = struct.pack("<H", (encoded >> 16)) + \
            struct.pack("<H", (encoded & 0xffff))
        return struct.unpack("<I", encoded)[0]


    # patch the referencing instruction to point to imp instead of selref and create an xref from msgSend to imp
    # selXref: address of selref's xref, which will be patched to point to imp if it exists and can be found
    def fixXref(self, eh, classes, clsName, selRefVA, isInstance, selXref, msgSendXref, userData):
        if clsName not in classes:
            logging.debug("class %s not found in objc_data section" % clsName)
            return
        funcVA = None
        # search stored class data for selref->funcVA tuple
        if isInstance:
            type_ = "instance"
        else:
            type_ = "class"
        for c in classes[clsName][type_]:
            if c[0] == selRefVA:
                funcVA = c[1]
                isAmbiguous = c[2]
                break
        if funcVA is None:
            logging.debug("selref@%s not found for class %s" %
                          (eh.hexString(selRefVA), clsName))
            return

        # if isAmbiguous == False:
        #    logging.debug("this selector is not ambiguous, we will fix it later!")
        try:
            if selXref not in userData["selXrefs"]:
                userData["selXrefs"][selXref] = []
            userData["selXrefs"][selXref].append(msgSendXref)
        except Exception as e:
            logging.debug("exception fixing xref @%s: %s" % (eh.hexString(userData["currAddr"]), e))
            print("exception fixing xref @%s: %s" % (eh.hexString(userData["currAddr"]), e))
            return

        # add xref to func and change instruction to point to function instead of selref
        # xref comes from call to msgSend, not from the sel xref
        idc.add_dref(msgSendXref, funcVA, idc.dr_I | idc.XREF_USER)
        # for both ARM archs, we change the LDR instruction to a BL instruction as its the only way I know how to get IDA
        # to make a clickable link to an objc method considering the comment bug
        reg = idc.print_operand(selXref, 0)
        srcOpnd = idc.print_operand(selXref, 1)
        if eh.arch == unicorn.UC_ARCH_ARM:
            if eh.isThumbMode(selXref):
                # change instructions to a BLX
                # if target is not 4 byte aligned, bump it up so IDA gets the xref
                logging.debug("fixing xref for imp %s" % eh.hexString(funcVA))
                target = funcVA
                if target % 4 != 0:
                    logging.debug("target is not 4-byte aligned, adding 2")
                    target += 2
                if "er16:" != srcOpnd[5:10]:
                    # skip 8 bytes to skip over upper MOV
                    userData["patchedSelRefs"][selXref] = (reg, 8)
                else:
                    userData["patchedSelRefs"][selXref] = (reg, 4)

                patchVal = self.assembleThumbBLXIns(eh, selXref, target)
                idc.patch_dword(selXref, patchVal)
                self.fixedSelXRefs.append(selXref)
                logging.debug("selector xref fixed!")
            else:
                # i don't have an example of ARM mode objective-c code to work with
                logging.debug(
                    "ARMv7 ARM mode not currently supported for xref patching")
                self.fixedSelXRefs.append(selXref)
                pass
        elif eh.arch == unicorn.UC_ARCH_ARM64:
            userData["patchedSelRefs"][selXref] = (reg, 4)
            if funcVA - selXref < 0:
                patchVal = (((funcVA - selXref) / 4) & 0xffffff) | 0x97000000
            else:
                patchVal = ((funcVA - selXref) / 4) | 0x94000000
            idc.patch_dword(selXref, patchVal)
            self.fixedSelXRefs.append(selXref)
            logging.debug("selector xref fixed!")
        elif eh.arch == unicorn.UC_ARCH_X86:
            # 7 is size of instruction
            offs = funcVA - selXref - 7
            # change RIP-relative address
            idc.patch_dword(selXref + 3, offs)
            # change from mov to lea
            idc.patch_byte(selXref + 1, 0x8D)
            self.fixedSelXRefs.append(selXref)
            logging.debug("selector xref fixed!")

    # store the sel->imp mapping for a given method in our classes dict
    def processMethod(self, eh, clsName, methodVa, classes, type_):
        objc2ClassMethImpOffs = 2 * eh.size_pointer
        isAmbiguous, isMsgRef, selRefVA = self.getRefPtr(eh, methodVa)
        if selRefVA is None:
            return
        funcVA = eh.derefPtr(methodVa + objc2ClassMethImpOffs)
        if eh.arch == unicorn.UC_ARCH_ARM:
            # remove last bit in case of thumb mode address
            funcVA = funcVA & ~1

        # adjust pointer to beginning of message_ref struct to get xrefs
        if isMsgRef:
            selRefVA -= eh.size_pointer

        # this shouldn't happen now
        if selRefVA in map(lambda x: x[0], classes[clsName][type_]):
            logging.debug("class name: %s - method type: %s - duplicate selref VA: %s, ignoring.." %
                          (clsName, type_, eh.hexString(selRefVA)))
        else:
            logging.debug("class name: %s - method type: %s - selref VA: %s - function VA: %s - ambiguous: %s" %
                          (clsName, type_, eh.hexString(selRefVA), eh.hexString(funcVA), isAmbiguous))
            classes[clsName][type_].append((selRefVA, funcVA, isAmbiguous))

    # collect imp and sel/msg ref pointers


    def getClassData(self, eh):
        objc2ClassSize = 5 * eh.size_pointer
        objc2ClassInfoOffs = 3 * eh.size_pointer
        objc2MethSize = 3 * eh.size_pointer
        objc2ClassBaseMethsOffs = 4 * eh.size_pointer
        objc2CatInstMethsOffs = 2 * eh.size_pointer
        objc2CatClsMethsOffs = 3 * eh.size_pointer
        classes = {}
        if self.objcData is None:
            return classes
            
        for va in range(self.objcData[0], self.objcData[1], objc2ClassSize):
            if "_OBJC_METACLASS_$_" in idc.get_name(va, idc.ida_name.GN_VISIBLE):
                continue
            clsName = self.formatName(idc.get_name(va, idc.ida_name.GN_VISIBLE))
            logging.debug("walking classes @%s: %s" % (eh.hexString(va), clsName))
            classes[clsName] = {"class": [], "instance": []}

            # get instance methods first, if class method has same name as instance method, ignore it which is not great
            baseMethodsVA = idc.get_name_ea_simple("_OBJC_INSTANCE_METHODS_" + clsName)
            if baseMethodsVA != idc.BADADDR and baseMethodsVA != 0:
                count = idc.get_wide_dword(baseMethodsVA + eh.size_DWORD)
                baseMethodsVA += eh.size_DWORD * 2  # advance to start of class methods array

                for va2 in range(baseMethodsVA, baseMethodsVA + objc2MethSize * count, objc2MethSize):
                    self.processMethod(eh, clsName, va2, classes, "instance")

            baseMethodsVA = idc.get_name_ea_simple("_OBJC_CLASS_METHODS_" + clsName)
            if baseMethodsVA != idc.BADADDR and baseMethodsVA != 0:
                count = idc.get_wide_dword(baseMethodsVA + eh.size_DWORD)
                baseMethodsVA += eh.size_DWORD * 2  # advance to start of class methods array

                for va2 in range(baseMethodsVA, baseMethodsVA + objc2MethSize * count, objc2MethSize):
                    self.processMethod(eh, clsName, va2, classes, "class")

        # we don't use idc.get_name_ea_simple to find the methods for categories because IDA's naming is too difficult to
        # parse/format
        if self.objcCatList:
            for va in range(self.objcCatList[0], self.objcCatList[1], eh.size_pointer):
                clsName = self.formatName(idc.get_name(eh.derefPtr(va), idc.ida_name.GN_VISIBLE))
                logging.debug("walking category classes @%s: %s" %
                              (eh.hexString(va), clsName))
                classes[clsName] = {"class": [], "instance": []}
                catVA = eh.derefPtr(va)

                # class methods
                catMethsVA = eh.derefPtr(catVA + objc2CatClsMethsOffs)
                if catMethsVA == 0:
                    continue
                count = idc.get_wide_dword(catMethsVA + eh.size_DWORD)
                catMethsVA += eh.size_DWORD * 2  # advance to start of methods array

                for va2 in range(catMethsVA, catMethsVA + objc2MethSize * count, objc2MethSize):
                    self.processMethod(eh, clsName, va2, classes, "class")

                # instance methods
                catMethsVA = eh.derefPtr(catVA + objc2CatInstMethsOffs)
                if catMethsVA == 0:
                    continue
                count = idc.get_wide_dword(catMethsVA + eh.size_DWORD)
                catMethsVA += eh.size_DWORD * 2  # advance to start of methods array

                for va2 in range(catMethsVA, catMethsVA + objc2MethSize * count, objc2MethSize):
                    self.processMethod(eh, clsName, va2, classes, "instance")

        return classes

    # uses iterate feature of flare_emu: for each xref to objc msgSend variants
    # patches program bytes to change sel ref pointers to implementation pointers for objc methods
    # adds objc-like syntax comments for each msgSend call


    def processObjc(self):
        userData = {}
        userData["selXrefs"] = {}
        eh = flare_emu.EmuHelper()
        classes = self.getClassData(eh)
        logging.debug("%d classes found" % len(classes.keys()))

        # get xrefs to objc_msgSend variants
        xrefs = list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSend")))
        xrefs.extend(list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSend_fixup"))))
        xrefs.extend(list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSend_stret"))))
        xrefs.extend(list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSend_fpret"))))
        xrefs.extend(list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSendSuper2"))))
        xrefs.extend(
            list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSendSuper2_stret"))))
        xrefs.extend(list(idautils.XrefsTo(idc.get_name_ea_simple("_objc_msgSendSuper_stret"))))
        logging.debug("%d initial xrefs to objc_msgSend variants" % len(xrefs))

        # build user data for emu callback
        userData["classes"] = classes
        userData["msgSendXrefs"] = []
        emuFuncs = set([])
        # get paths to initial msgSend xrefs
        targets = []
        for x in xrefs:
            funcStart = idc.get_func_attr(x.frm, idc.FUNCATTR_START)
            funcEnd = idc.get_func_attr(x.frm, idc.FUNCATTR_END)
            if funcStart == idc.BADADDR:
                continue
            emuFuncs.add((funcStart, funcEnd))
            if idc.print_insn_mnem(x.frm) not in self.callMnems:
                continue
            # get unique idautils.Functions from xrefs that we need to emulate
            userData["msgSendXrefs"].append(x.frm)
            targets.append(x.frm)

        # look for other possible msgSend calls that IDA missed
        userData["possibleMsgSendXrefs"] = []
        for func in emuFuncs:
            addr = func[0]
            # scan each function with a known msgSend xref for more
            while addr <= func[1]:
                dis = idc.generate_disasm_line(addr, 0)
                # is this instruction a "call reg" and IDA hasn't already identified it as something?
                if ((dis[:4] == "call" or dis[:2] == "BL") and ";" not in dis and
                        addr not in userData["msgSendXrefs"] and
                        idc.get_operand_type(addr, 0) == 1):
                    userData["possibleMsgSendXrefs"].append(addr)
                    targets.append(addr)
                addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))

        userData["selXrefs"] = {}
        userData["patchedSelRefs"] = {}
        if eh.arch == unicorn.UC_ARCH_ARM:
            emuHook = self.objc2AnalyzeHookARM
        elif eh.arch == unicorn.UC_ARCH_ARM64:
            emuHook = self.objc2AnalyzeHookARM64
        elif eh.arch == unicorn.UC_ARCH_X86 and eh.mode == unicorn.UC_MODE_64:
            emuHook = self.objc2AnalyzeHookX64
        else:
            logging.debug("unsupported architecture, quitting..")

        eh.iterate(targets, self.targetCallback, preEmuCallback=self.preEmuCallback,
                   callHook=self.callHook, instructionHook=emuHook, hookData=userData, resetEmuMem=True)

        # reload with patches
        eh.initEmuHelper()
        eh.reloadBinary()


    # parses ivar type encoding and returns magicVal for objc syntax string representation of ivar
    def getIvarInfo(self, eh, ivarPtr, userData):
        objc2IvarTypeOffs = 2 * eh.size_pointer
        objc2IvarNameOffs = eh.size_pointer
        if eh.size_pointer == 4:
            magicMask = self.magicMask32
        else:
            magicMask = self.magicMask64
        for x in idautils.XrefsTo(ivarPtr):
            if idc.get_segm_name(x.frm) == "__objc_const":
                typeStrPtr = eh.derefPtr(x.frm + objc2IvarTypeOffs)
                namePtr = eh.derefPtr(x.frm + objc2IvarNameOffs)
                typeStr = eh.getIDBString(typeStrPtr)
                varName = eh.getIDBString(namePtr)
                ptr = ""
                cmtStr = ""
                clsName = ""
                while typeStr[0] == "^":
                    ptr += "*"
                    typeStr = typeStr[1:]
                if len(ptr) > 0:
                    ptr = " " + ptr

                if typeStr[0] == "[":
                    m = re.match(r"\[([\d]+)([\^]*)(.+)\]", typeStr)
                    if m:
                        if len(m.group(2)) > 0:
                            ptr = " " + "*" * len(m.group(2))
                        cmtStr = "%s-width array of "
                        typeStr = m.group(3)

                if typeStr[0] == "@" and len(typeStr) > 1:
                    clsName = typeStr[2:-1]
                    cmtStr += "(%s *)%s" % (clsName, varName)
                elif typeStr == "@":
                    clsName = ""
                    cmtStr += "(id)%s" % varName
                elif typeStr == "c":
                    clsName = ""
                    cmtStr += "(char)%s" % varName
                elif typeStr == "*":
                    clsName = ""
                    cmtStr += "(char *)%s" % varName
                elif typeStr == "i":
                    clsName = ""
                    cmtStr += "(int%s)%s" % (ptr, varName)
                elif typeStr == "s":
                    clsName = ""
                    cmtStr += "(short%s)%s" % (ptr, varName)
                elif typeStr == "l":
                    clsName = ""
                    cmtStr += "(long%s)%s" % (ptr, varName)
                elif typeStr == "q":
                    clsName = ""
                    cmtStr += "(long long%s)%s" % (ptr, varName)
                elif typeStr == "C":
                    clsName = ""
                    cmtStr += "(unsigned char%s)%s" % (ptr, varName)
                elif typeStr == "I":
                    clsName = ""
                    cmtStr += "(unsigned int%s)%s" % (ptr, varName)
                elif typeStr == "S":
                    clsName = ""
                    cmtStr += "(unsigned short%s)%s" % (ptr, varName)
                elif typeStr == "L":
                    clsName = ""
                    cmtStr += "(unsigned long%s)%s" % (ptr, varName)
                elif typeStr == "Q":
                    clsName = ""
                    cmtStr += "(unsigned long long%s)%s" % (ptr, varName)
                elif typeStr == "f":
                    clsName = ""
                    cmtStr += "(float%s)%s" % (ptr, varName)
                elif typeStr == "d":
                    clsName = ""
                    cmtStr += "(double%s)%s" % (ptr, varName)
                elif typeStr == "B":
                    clsName = ""
                    cmtStr += "(bool%s)%s" % (ptr, varName)
                elif typeStr == "v":
                    clsName = ""
                    cmtStr += "(void%s)%s" % (ptr, varName)
                elif typeStr == ":":
                    clsName = ""
                    cmtStr += "(SEL%s)%s" % (ptr, varName)
                elif typeStr[0] == "{":
                    m = re.match(r"\{(.+)\=.*\}", typeStr)
                    if m:
                        cmtStr += "(struct %s%s)%s" % (m.group(1), ptr, varName)
                elif typeStr[0] == "(":
                    m = re.match(r"\((.+)\=.*\)", typeStr)
                    if m:
                        cmtStr += "(union %s%s)%s" % (m.group(1), ptr, varName)
                elif typeStr == "?":
                    clsName = ""
                    cmtStr += "(unknown%s)%s" % (ptr, varName)
                if cmtStr == "":
                    logging.debug("couldn't decode ivar type %s for ivar @%s" % (
                        typeStr, eh.hexString(ivarPtr)))
                    cmtStr = "(??)%s" % varName
                userData["magicVals"].append((cmtStr, clsName))
                ret = magicMask | userData["magicValsCount"]
                userData["magicValsCount"] += 1
                logging.debug("returning ivar magicVal for %s for ivar @%s" % (cmtStr, eh.hexString(ivarPtr)))
                return ret


    def preEmuCallback(self, eh, userData, funcStart):
        userData["magicVals"] = []
        userData["magicValsCount"] = 0
        if eh.size_pointer == 4:
            magicMask = self.magicMask32
        else:
            magicMask = self.magicMask64
        # get "self" id if in objc function
        clsName = None
        funcName = idaapi.get_func_name(funcStart)
        if funcName[0] in ["-", "+"] and "[" in funcName and "]" in funcName and " " in funcName:
            shortClsName = clsName = funcName[2:funcName.find(" ")]
            if "(" in clsName:
                clsName = "_OBJC_CATEGORY_" + \
                    clsName[:clsName.find(
                        "(")] + "_$_" + clsName[clsName.find("(") + 1:clsName.find(")")]
                shortClsName = shortClsName[:shortClsName.find(
                    "(")] + "_" + shortClsName[shortClsName.find("(") + 1:shortClsName.find(")")]
            else:
                clsName = "_OBJC_CLASS_$_" + clsName
        if clsName:
            if funcName[0] == "+":
                # this is a class method, use classRef
                self_ = idc.get_name_ea_simple(clsName)
                # assume rdx will hold an instance of the class
                userData["magicVals"].append(
                    ("(%s *)instance" % shortClsName, shortClsName))
                inst = magicMask | userData["magicValsCount"]
                userData["magicValsCount"] += 1
                eh.uc.reg_write(eh.regs["arg3"], inst)
            elif funcName[0] == "-":
                # this is an instance method, use magic value to store "self"
                userData["magicVals"].append(
                    ("(%s *)self" % shortClsName, shortClsName))
                self_ = magicMask | userData["magicValsCount"]
                userData["magicValsCount"] += 1
            eh.uc.reg_write(eh.regs["arg1"], self_)


if __name__ == '__main__':
    Objc2Analyzer()
