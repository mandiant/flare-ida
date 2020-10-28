############################################
##Author: James T. Bennett
##Objective-C xrefs helper IDApython script
############################################

########################################################################
# Copyright 2019 FireEye
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

import struct

from ida_bytes import get_bytes

from idaapi import add_dref
from idaapi import get_inf_structure

from idautils import Segments
from idautils import XrefsTo

from ida_bytes import patch_dword
from ida_kernwin import msg

from idc import BADADDR
from idc import dr_I
from idc import get_func_name
from idc import get_segm_end
from idc import get_segm_name
from idc import get_strlit_contents
from idc import get_wide_dword,get_qword
from idc import print_insn_mnem
from idc import XREF_USER


DWORD_SIZE=4
QWORD_SIZE=8
POINTER_SIZE=8

ARCH_X86_64=0
ARCH_ARM64=1
ARCH_UNKNOWN=100

class AArch64LDRInstruction(object):
    """A class to decode and patch arm64 LDR (literal) instructions
    
    Decodes instruction byte string into opcode, offset, and register
    Provides method to patch offset and regenerate instruction bytestring
    
    """
    ENDIANNESS_BIG=0
    ENDIANNESS_LITTLE=1
    def __init__(self,instruction_bytes,endianness=1):
        """Decode the byte string for an arm64 LDR (literal) instruction
        
        
        Arguments:
            instruction_bytes {string} -- Four-byte string that represents the instruction
        
        Keyword Arguments:
            endianness {number} -- Whether the instruction should be decoded as big or little endian (default: ENDIANNESS_LITTLE )
        
        Raises:
            Exception -- [Invalid instruction length]
            Exception -- [Invalid endianness]
        """
        if not len(instruction_bytes)==4:
            raise Exception("Invalid instruction length: %d" % len(instruction_bytes))
        if endianness != self.ENDIANNESS_BIG and endianness != self.ENDIANNESS_LITTLE:
            raise Exception("Invalid endianness value.")

        self.endianness=endianness
        self.instruction_bytes=instruction_bytes
        self.instruction_int=self.__unpack(instruction_bytes)
        self.__decode_ldr()
        

    def __unpack(self,bytes):
        if self.endianness==self.ENDIANNESS_LITTLE:
            fmt="<I"
        else:
            fmt=">I"

        return struct.unpack(fmt,bytes)[0]

    def __pack(self,number):
        if self.endianness==self.ENDIANNESS_LITTLE:
            fmt="<I"
        else:
            fmt=">I"
        return struct.pack(fmt,number)

    def __shiftL32(self,num,count):
        return (num<<count)&0xffffffff

    def __shiftR32(self,num,count):
        return (num>>count)&0xffffffff

    def __decode_ldr(self):
        ldr_literal_64_op=0b01011000
        op=self.__shiftR32(self.instruction_int,24)
        if not op==ldr_literal_64_op:
            raise Exception("Not a valid LDR (literal) instruction)")
        self.op=op
        imm19_mask=self.__shiftL32(self.__shiftR32(0x00ffffff,5),5)
        
        imm19=self.__shiftR32((self.instruction_int&imm19_mask),5)
        offset=imm19*4 #shift imm19<<2
        
        self.offset=offset

        rt_mask=0b11111
        rt=self.instruction_int&rt_mask

        self.rt=rt

    def patch_offset(self,new_offset):
        """Change the memory offset for this instruction
        
        Update the memory offset this instruction should load from and regenerate the byte string.
        
        Arguments:
            new_offset {} -- [New offset to be encoded into the LDR instruction]
        """
        new_offset=new_offset&0xffffffff
        imm19_mask=self.__shiftL32(self.__shiftR32(0x00ffffff,5),5)
        imm19=self.__shiftR32(new_offset,2) #rshift 2 because imm19=offset/4
        imm19=self.__shiftL32(imm19,5)
        imm19=imm19&imm19_mask

        op=self.op
        op_shifted=self.__shiftL32(op,24)
        instruction_int=(op_shifted|imm19|self.rt)&0xffffffff
        instruction_bytes=self.__pack(instruction_int)
        self.instruction_int=instruction_int
        self.instruction_bytes=instruction_bytes
        self.__decode_ldr()


class ObjCException(Exception):
    pass




class ObjcClass(object):
    """Class to parse an Objective-C class structure
    """
    OBJC2_CLASS_RO_OFFSET=0x20 #offset into a _class_t of the ro member
    OBJC2_CLASS_RO_BASE_METHODS_OFFSET=0x20 #offset into a _class_ro_t of the baseMethods member
    OBJC2_CLASS_RO_NAME_OFFSET=0x18
    def __init__(self,objc_class_va,segment_map,arch=ARCH_X86_64):
        """Create a new ObjcClass instance
                
        Arguments:
            objc_class_va {number} -- Virtual address of the Objective-C class to parse
            segment_map {dictionary} -- A dictionary mapping segment names to a start/end virtual address tuple
        
        Keyword Arguments:
            arch {number} -- CPU architecture. Either ARCH_X86_64 or ARM64 (default: {ARCH_X86_64})
        """
        self.arch=arch
        self.segment_map=segment_map
        class_ro_va=get_qword(objc_class_va+self.OBJC2_CLASS_RO_OFFSET)
        self.name_pointer=get_qword(class_ro_va+self.OBJC2_CLASS_RO_NAME_OFFSET)
        self.method_list=[]
        if class_ro_va == BADADDR or class_ro_va==0:
            self.class_ro_va=None
            return
        self.class_ro_va=class_ro_va

        class_methods_va=get_qword(class_ro_va+self.OBJC2_CLASS_RO_BASE_METHODS_OFFSET)

        if class_methods_va == BADADDR or class_methods_va==0:
            self.class_methods_va=None
            return
        self.class_methods_va=class_methods_va
        msg("Class found at virtual address: 0x%x\n" % objc_class_va)
        msg("Class name: %s\n" % get_strlit_contents(self.name_pointer))
        #Parse the method_list_t struct and build a list of methods
        self.method_list=ObjcMethodList(class_methods_va,segment_map,arch=arch)

    def patched_xrefs(self):
        if len(self.method_list)>0:
            return self.method_list.patched_xrefs()
        else:
            return []




class ObjCMethodAbstract(object):
    """Abstract class to parse Objective-C method structures
    
    This class cannot be instantiated as-is. It must be extended to override add_method_xref()
    """
    
    OBJC_METHOD_SIZE=0x18 #sizeof(struct _objc_method)
    OBJC_METHOD_TYPE_OFFSET=8
    OBJC_METHOD_IMP_OFFSET=0x10
    #TODO: override for other architectures
    CALL_MNEMONIC="call"
    def __init__(self,method_va,segment_map):
        """Do not instantiate directly
        
        Arguments:
            method_va
            segment_map
        """
        msg("Found method at virtual address: 0x%x\n" % method_va)

        self.method_va=method_va
        self.segment_map=segment_map

        self.name_pointer=get_qword(method_va)
        self.method_type=get_qword(method_va+self.OBJC_METHOD_TYPE_OFFSET)
        self.method_pointer_va=method_va+self.OBJC_METHOD_IMP_OFFSET
        self.method_pointer=get_qword(self.method_pointer_va)
        self.patched_xrefs=[]
        objc_selrefs = segment_map["__objc_selrefs"]
        objc_msgrefs  = segment_map["__objc_msgrefs"]
        objc_const    = segment_map["__objc_const"]
        msg("Method name: %s\n" % get_func_name(self.method_pointer))
        is_msg_ref,selector_ref,const_ref_count=self.get_xref(objc_selrefs,objc_msgrefs,objc_const)
        self.is_msg_ref=is_msg_ref
        self.const_ref_count=const_ref_count
        if not selector_ref:
            msg("No selref found.\n")
            self.selector_ref=None
            return
        if const_ref_count == 1:
            #We can only work with unambiguous situations where there is exactly one const reference 
            #to the selector.
            self.selector_ref=selector_ref
        else:
            msg("Selector ref count not exactly 1. Potentially ambiguous: %d" % const_ref_count)
            # Otherwise this same selector is used by more than one class. (Or none at all)
            self.selector_ref=None
            return

        
        self.sel_ref_va=self.selector_ref.frm
        if is_msg_ref:
            # adjust pointer to beginning of message ref struct to get xrefs
            self.sel_ref_va-=POINTER_SIZE

        msg("selref VA: 0x%X - function VA: 0x%X\n" % (self.sel_ref_va, self.method_pointer))
        #Find all the references to this *selref* (note: not the string itself but the selref)
        #These should precede calls to the method
        #Patch the references to the selref with a reference to the method implementation
        self.walk_selector_refs()


    def get_xref(self,objc_selrefs,objc_msgrefs,objc_const):
        #We're looking for references to the selector string (think char **)
        #Which is either a selref, a msgref, or a pointer to the selector from the class's const method list
        name_ptr = self.name_pointer
        is_msg_ref=False
        selector_ref=None
        #how many references from __objc_const are there? This indicates how many classes
        #reference this selector
        const_ref_count=0
        for xref in XrefsTo(name_ptr):
            #Is this cross reference in the range of selector references?
            if objc_selrefs and xref.frm >= objc_selrefs[0] and xref.frm < objc_selrefs[1]:
                is_msg_ref=False
                selector_ref=xref
            #else, is this cross reference in the range of msg references?
            elif objc_msgrefs and xref.frm >= objc_msgrefs[0] and xref.frm < objc_msgrefs[1]:
                is_msg_ref=True
                selector_ref=xref
            #else, is this cross reference a pointer from a (const) method list?
            elif objc_const and xref.frm >= objc_const[0] and xref.frm < objc_const[1]:
                const_ref_count += 1



        return (is_msg_ref,selector_ref,const_ref_count)

    def walk_selector_refs(self):
        #sel_ref_va is the address of the selref, which itself is a pointer to the selector string
        #we're looking for cross references *to* the the address of the selref
        #If we find ones we like and replace them with a cross reference to the actual method implementation, rather than the selector
        for xref in XrefsTo(self.sel_ref_va):
            if print_insn_mnem(xref.frm) == self.CALL_MNEMONIC:
                continue
            #We found a xref *from* somewhere *to* our selref. We need to replace that with a reference
            #To the actual method implementation
            method_xref=self.add_method_xref(xref)
            self.patched_xrefs.append(method_xref)

    def add_method_xref(self,xref):
        raise Exception("Unimplemented. Use architecture specific class that overrides add_method_xref()")



class ObjCMethodX86_64(ObjCMethodAbstract):
    """x86_64-specific class to parse Objective-C method structures
    
    Provides x86_64-specific implementation to patch method references in code.
    
    Extends:
        ObjCMethodAbstract
    
    """
    X86_64_MOV_INSTRUCTION_SIZE=7
    def __init__(self,method_va,segment_map):
        """
        Create an x86-64-specific Objective-C method object
        
        Arguments:
            method_va {number} -- Virtual address of the method structure to parse.
            segment_map {dictionary} -- A dictionary mapping segment names to a start/end virtual address tuple
        """
        super(ObjCMethodX86_64,self).__init__(method_va,segment_map)


    def add_method_xref(self,xref):
        msg("Adding cross reference to method implementation for %s\n" % get_func_name(self.method_pointer))
        
        #TODO: clean this up so it's more clear how we're parsing and patching the instruction
        #TODO: handle other potential instructions that could place a method selref into a register
        #TODO: sanity check what instruction we're actually working with before blindly deciding
        #       it's a 7-byte mov instruction

        add_dref(xref.frm,self.method_pointer,dr_I|XREF_USER)
        
        #offset is a rip-relative offset that gets added to rip and dereferenced
        #when this instruction is executed, rip will be pointing to the next instruction
        #meaning it has been incremented by 7 (the length of the mov instruction)
        offset=self.method_pointer-xref.frm-self.X86_64_MOV_INSTRUCTION_SIZE
        
        #this replaces  mov RSI, &selector with:
        #               mov RSI, &method
        #xref.frm is the address of the mov instruction
        #+3 (4th byte of the instruction)
        #is where the RIP-relative operand is that
        #will get dereferenced as a pointer
        patch_dword(xref.frm+3,offset)
        return ObjcMethodXref(xref.frm,self.method_pointer,xref.to)



class ObjCMethodArm64(ObjCMethodAbstract):
    """Arm64-specific class to parse Objective-C method structures
    
    Provides Arm64-specific implementation to patch method references in code.
    
    Extends:
        ObjCMethodAbstract
    
    """
    ARM64_INSTRUCTION_SIZE=4
    def __init__(self,method_va,segment_map):
        """
        Create an Arm64-specific Objective-C method object
        
        Arguments:
            method_va {number} -- Virtual address of the method structure to parse.
            segment_map {dictionary} -- A dictionary mapping segment names to a start/end virtual address tuple
        """
        super(ObjCMethodArm64,self).__init__(method_va,segment_map)

    def add_method_xref(self,xref):
        msg("Adding cross reference to method implementation for %s\n" % get_func_name(self.method_pointer))
        
        add_dref(xref.frm,self.method_pointer,dr_I|XREF_USER)

        offset=self.method_pointer-xref.frm
        
        instruction_bytes=get_bytes(xref.frm,self.ARM64_INSTRUCTION_SIZE)
        #TODO: are there other instructions that could reference a method selector
        #and then move the selector reference into a register?
        arm64_ldr=AArch64LDRInstruction(instruction_bytes)
        
        arm64_ldr.patch_offset(offset)

        patch_dword(xref.frm,arm64_ldr.instruction_int)
        return ObjcMethodXref(xref.frm,self.method_pointer,xref.to)


class ObjcMethodList(list):
    """A class to parse Objective-C method list structures
    
    Creates an iterable list of Object-C Method objects
    
    Extends:
        list
    """
    METHOD_LIST_OFFSET=DWORD_SIZE*2 # method_list array starts after entsize and method_count (both ints)
    OBJC_METHOD_CLASSES=[ObjCMethodX86_64,ObjCMethodArm64]
    def __init__(self,method_list_va,segment_map,arch=ARCH_X86_64):
        """Create a new list of Objective-C method objects
        
        Arguments:
            method_list_va {number} -- Virtual address where the Objective-C method list structure is located
            segment_map {dictionary} -- A dictionary mapping segment names to a start/end virtual address tuple
        
        Keyword Arguments:
            arch {number} -- CPU architecture. Either ARCH_X86_64 or ARM64 (default: {ARCH_X86_64})
        """
        super(ObjcMethodList,self).__init__()
        self.ObjCMethod=self.OBJC_METHOD_CLASSES[arch]
        self.method_list_va=method_list_va
        self.segment_map=segment_map

        objc_selrefs = segment_map["__objc_selrefs"]
        objc_msgrefs  = segment_map["__objc_msgrefs"]
        objc_const    = segment_map["__objc_const"]

        #Walk the method_list_t struct and parse out each _objc_method
        self.walk_methods(objc_selrefs,objc_msgrefs,objc_const)

    def walk_methods(self,objc_selrefs,objc_msgrefs,objc_const):
        msg("Walking methods starting at virtual address: 0x%x\n" % self.method_list_va)
        class_methods_va=self.method_list_va
        #deref the method list struct to get method count:
        count=get_wide_dword(class_methods_va+DWORD_SIZE)

        method_size=self.ObjCMethod.OBJC_METHOD_SIZE #sizeof(struct _objc_method)

        #skip first two dwords in the method_list struct
        class_methods_start=class_methods_va+self.METHOD_LIST_OFFSET
        
        class_methods_end=class_methods_start+(method_size*count)

        for va in range(class_methods_start,class_methods_end,method_size):
            #Parse this method struct and create a method object
            #If possible, the method will patch the IDB to replace references to its selector
            #with a reference to its implementation
            objc_method=self.ObjCMethod(va,self.segment_map)

            self.append(objc_method)

    def patched_xrefs(self):
        # this is equivalent to:
        # for method in self:
        #   for xref in method.patch_xrefs:
        #      ...add xref to a list...
        return [xref for method in self for xref in method.patched_xrefs]

class ObjcMethodXref(object):
    """A class to represent patched method crosss references
    
    """
    def __init__(self,frm_va,to_va,old_to_va):
        """Create a new ObjcMethodXref object
        
        Arguments:
            frm_va {number} -- Virtual address location of the reference
            to_va {[type]} -- Virtual address that is pointed to by the reference
            old_to_va {[type]} -- Virtual address that was pointed to by the reference prior to patching
        """
        self.frm_va=frm_va
        self.to_va=to_va
        self.old_to_va=old_to_va
        self.method_name=get_func_name(self.to_va)

    def __str__(self):
        return "[0x%x] --> %s"%(self.frm_va,self.method_name)

class ObjCMethodXRefs(list):
    """A class to parse Objective-C class and method structures
    
    Parses class and method structures and locates cross-references to the method selectors.
    If the class that references the selectors is unambiguous, all code references to the selectors
    are replaced with references to the method implementation.

    What results is an iterable list of all cross references that were patched.
    
    Extends:
        list
    """
    objc2ClassSize = 0x28

    def __init__(self,arch=ARCH_X86_64):
        """
        Create a new list of of method cross-references

        Keyword Arguments:
            arch {number} -- CPU architecture. Either ARCH_X86_64 or ARM64 (default: {ARCH_X86_64})
        """
        super(ObjCMethodXRefs,self).__init__()
        self.arch=arch

        segment_names=["__objc_data","__objc_selrefs","__objc_msgrefs","__objc_const"]

        segment_map=self.find_all_segments(segment_names)
        
        # Segment map looks like:
        # {
        #     "__objc_data":(obc_data_start_va,objc_data_end_va),
        #     ...
        # }
        
        for name in segment_names:
            if name not in segment_map:
                raise ObjCException("Couldn't find segment %s" % name)

        #Walk __objc_data and build a list of classes
        self.walk_classes(segment_map)

            

    def find_all_segments(self,segment_names):
        segments={name:None for name in segment_names}
        for seg_va in Segments():
            seg_name=get_segm_name(seg_va)
            if seg_name in segment_names:
                segments[seg_name]=(seg_va,get_segm_end(seg_va))
        return segments

    def walk_classes(self,segment_map):
        msg("Walking classes\n")
        classes=[]
        objc_data_start,objc_data_end=segment_map["__objc_data"]
        for va in range(objc_data_start,objc_data_end,self.objc2ClassSize):
            objc_class=ObjcClass(va,segment_map,arch=self.arch)
            classes.append(objc_class)
            self.extend(objc_class.patched_xrefs())
        self.classes=classes


def detect_arch():
    #heuristically determine what architecture we're on
    #only x86-64 and arm64 are supported
    is_le=False
    bits=0
    info = get_inf_structure()
    arch=ARCH_UNKNOWN
    if info.is_64bit():
        bits=64
    elif info.is_32bit():
        bits=32
    else:
        bits=16

    if not info.is_be():
        is_le=True

    procname=info.procName
    if bits==64 and is_le:
        if procname=="ARM":
            msg("Detected architecture: arm64\n")
            arch=ARCH_ARM64
        elif procname=="metapc":
            msg("Detected architecture: x86_64\n")
            arch=ARCH_X86_64

    return arch






def main():
    arch=detect_arch()
    xref_list=ObjCMethodXRefs(arch=arch)
    msg("Patched the following method references:\n")
    for xref in xref_list:
        msg("%s\n" % str(xref))

if __name__ == '__main__':
    main()
    

