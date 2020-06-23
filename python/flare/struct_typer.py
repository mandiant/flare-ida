#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2013 Mandiant
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
# Attempts to set types for struct members based on searching for
# like-named types in IDA's type libraries.
#
########################################################################

import re
import sys
import ctypes
import logging

from PyQt5 import QtWidgets
from PyQt5 import QtCore 
from PyQt5.QtCore import Qt

import idc
import idaapi
import idautils

from . import jayutils
from .struct_typer_widget import Ui_Dialog

# get the IDA version number
ida_major, ida_minor = list(map(int, idaapi.get_kernel_version().split(".")))
using_ida7api = (ida_major > 6)

logger = None

############################################################
# In older IDAPython, several type-related functions aren't accessible
# so have to do things with ctypes
if not using_ida7api:
    idaname = "ida64" if idc.__EA64__ else "ida"
    if sys.platform == "win32":
        g_dll = ctypes.windll[idaname + ".wll"]
    elif sys.platform == "linux2":
        g_dll = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        g_dll = ctypes.cdll["lib" + idaname + ".dylib"]

    ############################################################
    # Specifying function types for a few IDA SDK functions to keep the 
    # pointer-to-pointer args clear.
    get_named_type = g_dll.get_named_type
    get_named_type.argtypes = [
        ctypes.c_void_p,                                #const til_t *ti,
        ctypes.c_char_p,                                #const char *name,
        ctypes.c_int,                                   #int ntf_flags,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const type_t **type=NULL,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const p_list **fields=NULL,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const char **cmt=NULL,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), #const p_list **fieldcmts=NULL,
        ctypes.POINTER(ctypes.c_ulong),                 #sclass_t *sclass=NULL,
        ctypes.POINTER(ctypes.c_ulong),                 #uint32 *value=NULL);
    ]

    print_type_to_one_line = g_dll.print_type_to_one_line
    print_type_to_one_line.argtypes = [
        ctypes.c_char_p,                #char  *buf,
        ctypes.c_ulong,                 #size_t bufsize,
        ctypes.c_void_p,                #const til_t *ti,
        ctypes.POINTER(ctypes.c_ubyte), #const type_t *pt,
        ctypes.c_char_p,                #const char *name = NULL,
        ctypes.POINTER(ctypes.c_ubyte), #const char *cmt = NULL,
        ctypes.POINTER(ctypes.c_ubyte), #const p_list *field_names = NULL,
        ctypes.POINTER(ctypes.c_ubyte), #const p_list *field_cmts = NULL);
    ]

############################################################

def manualTypeCopy(dest, destOff, destLen, src):
    '''Copies an IDA type 'string' to the given location'''
    i = 0
    while (i+destOff) < destLen:
        dest[i+destOff] = chr(src[i])
        if (src[i] == 0) or (src[i] == '\x00'):
            break
        i += 1

g_NUMBERS = '0123456789'
def stripNumberedName(name):
    '''Remove trailing unique ID like IDA does for same names'''
    idx = len(name) -1
    while idx >= 0:
        if (name[idx] == '_'):
            if (len(name)-1) == idx:
                #last char is '_', not allowed so return name
                return name
            else:
                #encountered a '_', strip here
                return name[:idx]
        if name[idx] in g_NUMBERS:
            #still processing tail
            pass
        else:
            #encountered unexpected sequence, just return name
            return name
        idx -= 1
    return name


def loadMembersIDA7(struc, sid):
    '''Returns list of tuples of (offset, memberName, member)'''
    #mixing idc & idaapi, kinda annoying but need low-level idaapi for a 
    # type access, but cant dig into structs...
    members = []
    off = idaapi.get_struc_first_offset(struc) 
    while off != idc.BADADDR:
        logger.debug('struc offset: 0x%x (%d)', off, off)
        member = idaapi.get_member(struc, off)
        if (member == 0) or (member is None):
            pass    #not really an error, i guess
        else:
            members.append( (off, idc.get_member_name(sid, off), member) )
        off = idaapi.get_struc_next_offset(struc, off )
    members.sort(key = lambda mem: mem[0])
    return members

def loadMembers(struc, sid):
    '''Returns list of tuples of (offset, memberName, member)'''
    #mixing idc & idaapi, kinda annoying but need low-level idaapi for a 
    # type access, but cant dig into structs...
    if using_ida7api:
        return loadMembersIDA7(struc, sid)
    members = []
    off = g_dll.get_struc_first_offset(struc) 
    while off >= 0:
        member = g_dll.get_member(struc, ctypes.c_int(off))
        if (member == 0) or (member is None):
            pass    #not really an error, i guess
        else:
            members.append( (off, idc.GetMemberName(sid, off), member) )
        off = g_dll.get_struc_next_offset(struc, ctypes.c_int(off) )
    members.sort(key = lambda mem: mem[0])
    return members

def loadStructs():
    idx = idaapi.get_first_struc_idx()
    existingStructs = []
    while idx != idc.BADADDR:
        tid = idaapi.get_struc_by_idx(idx)
        existingStructs.append(idaapi.get_struc_name(tid))
        idx = idaapi.get_next_struc_idx(idx)
    existingStructs.sort()
    return existingStructs

############################################################
g_DefaultPrefixRegexp = r'field_.*_'

class StructTyperWidget(QtWidgets.QDialog):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        try:
            logger.debug('StructTyperWidget starting up')
            self.ui=Ui_Dialog()
            self.ui.setupUi(self)
            self.ui.lineEdit.setText(g_DefaultPrefixRegexp)
            self.ui.checkBox.setChecked(Qt.Unchecked)
        except Exception as err:
            logger.exception('Error during init: %s', str(err))

    def getActiveStruct(self):
        if self.ui.listWidget.currentItem() is None:
            return None
        return str(self.ui.listWidget.currentItem().data(Qt.DisplayRole))

    def setStructs(self, structs):
        for name in structs:
            item = QtWidgets.QListWidgetItem(name)
            self.ui.listWidget.addItem(item)

    def getRegPrefix(self):
        if self.ui.checkBox.isChecked():
            return str(self.ui.lineEdit.text())
        return ''

############################################################

class StructTypeRunner(object):

    def run(self):
        try:
            logger.debug('Starting up')
            dlg = StructTyperWidget()
            dlg.setStructs(loadStructs())
            oldTo = idaapi.set_script_timeout(0)
            res = dlg.exec_()
            idaapi.set_script_timeout(oldTo)
            if res == QtWidgets.QDialog.Accepted:
                regPrefix = dlg.getRegPrefix()
                sid = None
                struc = None
                if dlg.ui.rb_useStackFrame.isChecked():
                    ea = idc.here()
                    if using_ida7api:
                        sid = idc.get_frame_id(ea)
                    else:
                        sid = idc.GetFrame(ea)
                    struc = idaapi.get_frame(ea)
                    logger.debug('Dialog result: accepted stack frame')
                    if (sid is None) or (sid == idc.BADADDR):
                        #i should really figure out which is the correct error case
                        raise RuntimeError('Failed to get sid for stack frame at 0x%x' % ea) 
                    if (struc is None) or (struc == 0) or (struc == idc.BADADDR):
                        raise RuntimeError('Failed to get struc_t for stack frame at 0x%x' % ea)
                    if using_ida7api:
                        pass
                    else:
                        #need the actual pointer value, not the swig wrapped struc_t
                        struc= int(struc.this)
                else:
                    structName = dlg.getActiveStruct()
                    if structName is None:
                        print("No struct selected. Bailing out")
                        return
                    logger.debug('Dialog result: accepted %s "%s"', type(structName), structName)
                    if using_ida7api:
                        sid = idc.get_struc_id(structName)
                    else:
                        sid = idc.GetStrucIdByName(structName)
                    if (sid is None) or (sid == idc.BADADDR):
                        #i should really figure out which is the correct error case
                        raise RuntimeError('Failed to get sid for %s' % structName) 
                    tid = idaapi.get_struc_id(structName)
                    if (tid is None) or (tid == 0) or (tid == idc.BADADDR):
                        #i should really figure out which is the correct error case
                        raise RuntimeError('Failed to get tid_t for %s' % structName)
                    if using_ida7api:
                        struc = idaapi.get_struc(tid)
                    else:
                        struc = g_dll.get_struc(tid)
                    if (struc is None) or (struc == 0) or (struc == idc.BADADDR):
                        raise RuntimeError('Failed to get struc_t for %s' % structName)
                foundMembers = self.processStruct(regPrefix, struc, sid)
                if dlg.ui.rb_useStackFrame.isChecked() and (foundMembers != 0):
                    #reanalyze current function if we're analyzing a stack frame & found some func pointers
                    if using_ida7api:
                        funcstart = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
                        funcend = idc.get_func_attr(idc.here(), idc.FUNCATTR_END)
                    else:
                        funcstart = idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_START)
                        funcend = idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_END)
                    if (funcstart != idc.BADADDR) and (funcend != idc.BADADDR):
                        if using_ida7api:
                            idc.plan_and_wait(funcstart, funcend)
                        else:
                            idc.AnalyzeArea(funcstart, funcend)
            elif res == QtWidgets.QDialog.Rejected:
                logger.info('Dialog result: canceled by user')
            else:
                logger.debug('Unknown result')
                raise RuntimeError('Dialog unknown result')
        except Exception as err:
            logger.exception("Exception caught: %s", str(err))

    def filterName(self, regPrefix, name):
        funcname = stripNumberedName(name)
        if len(regPrefix) != 0:
            reg = re.compile('('+regPrefix+')(.*)')
            m = reg.match(funcname)
            if m is not None:
                logger.debug('Stripping prefix: %s -> %s', name, m.group(2))
                funcname = m.group(2)
            else:
                #if it does not match, continue to see if it can still match
                pass
        return funcname

    def processStructIDA7(self, regPrefix, struc, sid):
        members = loadMembers(struc, sid)
        foundFunctions = 0
        for off, name, memb in members:
            funcname  = self.filterName(regPrefix, name)
            tup = idaapi.get_named_type(None, funcname, idaapi.NTF_SYMM)
            if tup is None:
                continue
            code, type_str, fields_str, cmt, field_cmts, sclass, value  = tup
            foundFunctions += 1
            tif = idaapi.tinfo_t()
            tif.deserialize(None, type_str, fields_str, cmt)
            if not tif.is_func():
                logger.debug('Found named type, but not a function: %s', funcname)
                continue
            tif.create_ptr(tif)
            ret = idaapi.set_member_tinfo(struc, memb, off, tif, 0)
            if ret != idaapi.SMT_OK:
                logger.info("Got set_member_tinfo ret code: %d" % ret)
            else:
                logger.info('set_member_tinfo: %s', tif.dstr())

    def processStruct(self, regPrefix, struc, sid):
        '''
        Returns the number of identified struct members whose type was found
        '''
        if using_ida7api:
            return self.processStructIDA7(regPrefix, struc, sid)
        til = ctypes.c_void_p.in_dll(g_dll, 'idati')
        members = loadMembers(struc, sid)
        foundFunctions = 0
        for off, name, memb in members:
            funcname  = self.filterName(regPrefix, name)


            typ_type = ctypes.POINTER(ctypes.c_ubyte)()
            typ_fields = ctypes.POINTER(ctypes.c_ubyte)()
            typ_cmt = ctypes.POINTER(ctypes.c_ubyte)()
            typ_fieldcmts = ctypes.POINTER(ctypes.c_ubyte)()
            typ_sclass = ctypes.c_ulong()
            value = ctypes.c_ulong()
            ret = get_named_type(
                    til,
                    funcname, 
                    idaapi.NTF_SYMM, 
                    ctypes.byref(typ_type),
                    ctypes.byref(typ_fields),
                    ctypes.byref(typ_cmt),
                    ctypes.byref(typ_fieldcmts),
                    ctypes.byref(typ_sclass),
                    ctypes.byref(value)
            )
            if ret == 0:
                logger.debug('Could not find %s', funcname)
            else:
                foundFunctions += 1
                if typ_type[0] != idaapi.BT_FUNC:
                    #not positive that the first type value has to be BT_FUNC or not...
                    # and whether it's important to only apply to funcs or not
                    logger.debug('Found named type, but not a function: %s', funcname)
                else:
                    type_arr = ctypes.create_string_buffer(0x400)
                    type_arr[0] = chr(idaapi.BT_PTR)
                    manualTypeCopy(type_arr, 1, len(type_arr), typ_type)
                    ret = g_dll.set_member_tinfo(
                        til,
                        struc,
                        memb,
                        ctypes.c_uint(0),
                        type_arr,
                        typ_fields,
                        ctypes.c_uint(0),
                    )
                    name_buffer = ctypes.create_string_buffer(0x400)
                    print_type_to_one_line(
                        name_buffer, 
                        len(name_buffer),
                        til,
                        typ_type,
                        funcname,
                        typ_cmt,
                        typ_fields,
                        typ_fieldcmts
                    )
                    if ret == 0:
                        logger.info('Failed to set_member_tinfo: %s', name_buffer.value)
                    else:
                        logger.info('set_member_tinfo: %s', name_buffer.value)
        return foundFunctions
            

def main():
    global logger
    #logger = jayutils.configLogger(__name__, logging.DEBUG)
    logger = jayutils.configLogger(__name__, logging.INFO)
    launcher = StructTypeRunner()
    launcher.run()

if __name__ == '__main__':
    main()
