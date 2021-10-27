#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2014 FireEye
#
# Fireye licenses this file to you under the Apache License, Version
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
# Mostly a glorified wrapper around the apply_callee_tinfo() idasdk function.
# Useful for when IDA doesn't apply stack analysis to an indirect call,
# and you can identify the function prototype during reverse engineering.
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

from .apply_callee_type_widget import Ui_ApplyCalleeDialog

logger = None

# get the IDA version number
ida_major, ida_minor = list(map(int, idaapi.get_kernel_version().split(".")))
using_ida7api = (ida_major > 6)

MSDN_MACROS = [
' _In_ ',
' _Out_ ',
' _Inout_ ',
]


def predFunc(*args):
    print('Running predFunc: %s' % str(args))

def manualTypeCopy(dest, destOff, destLen, src):
    '''Copies an IDA type 'string' to the given location'''
    i = 0
    while (i+destOff) < destLen:
        dest[i+destOff] = chr(src[i])
        if (src[i] == 0) or (src[i] == '\x00'):
            break
        i += 1



class ApplyCalleeTypeRunner(object):
    #def __init__(self):
    #    self.logger = jayutils.getLogger('ApplyCalleeType')

    def getUserDeclType(self, decl):
        tinfo = idaapi.tinfo_t()
        #logger.debug('Trying to parse declaration: %r', decl)
        ret = idaapi.parse_decl(tinfo, idaapi.cvar.idati, decl, idaapi.PT_TYP)
        #logger.debug('Return from parse_decl2: %r', ret)
        if ret is None:
            logger.info('parse_decl failed')
            return None
        return tinfo

    def getLocalType(self):
        ret = idaapi.choose_local_tinfo(idaapi.cvar.idati, 'Choose local type to apply', None, 0, None)
        if not ret:
            logger.debug('User canceled. Bailing out')
            return
        #ret is a numbered type rather than the name
        tinfo = idaapi.tinfo_t()
        tinfo.get_numbered_type(idaapi.cvar.idati, ret)
        return tinfo

    def getBuiltinGlobalType(self):

        # Ensure proper IDA Python methods are exposed
        if hasattr(idaapi, "get_named_type") and hasattr(idaapi.tinfo_t, "deserialize"):
            return self.getBuiltinGlobalTypePython()

        # Fall back to calling exports directly with Ctypes
        else:
            return self.getBuiltinGlobalTypeCtypes()

    def getBuiltinGlobalTypePython(self):
        logger.debug('Getting GlobalType the Python way')
        sym = idaapi.til_symbol_t()
        if using_ida7api:
            ret = idaapi.choose_named_type(sym, idaapi.get_idati(), 'Choose type to apply', idaapi.NTF_SYMM, None)
        else:
            ret = idaapi.choose_named_type2(idaapi.cvar.idati, 'Choose type to apply', idaapi.NTF_SYMM, None, sym)
        if not ret:
            logger.debug('User canceled. Bailing out')
            return

        tuple = idaapi.get_named_type(sym.til, sym.name, 0)

        if tuple == None:
            logger.debug('Could not find %s', sym.name)
            return

        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(sym.til, tuple[1], tuple[2])

        return tinfo

    def getBuiltinGlobalTypeCtypes(self):
        logger.debug('Getting GlobalType the Ctypes way')

        ############################################################
        # Several type-related functions aren't accessibly via IDAPython
        # so have to do things with ctypes
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

        sym = idaapi.til_symbol_t()
        #dang - no predicate func support via idapython :(
        #idaapi.choose_named_type2(idaapi.cvar.idati, 'Choose type to apply', idaapi.NTF_SYMM, predFunc, sym)
        ret = idaapi.choose_named_type2(idaapi.cvar.idati, 'Choose type to apply', idaapi.NTF_SYMM, None, sym)
        if not ret:
            logger.debug('User canceled. Bailing out')
            return
        til = sym.til
        funcname = sym.name

        typ_type = ctypes.POINTER(ctypes.c_ubyte)()
        typ_fields = ctypes.POINTER(ctypes.c_ubyte)()
        typ_cmt = ctypes.POINTER(ctypes.c_ubyte)()
        typ_fieldcmts = ctypes.POINTER(ctypes.c_ubyte)()
        typ_sclass = ctypes.c_ulong()
        value = ctypes.c_ulong()
        ret = get_named_type(
                int(til.this),
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
            return
        ########################################
        # the following isn't needed, as moved to tinfo_t usage
        #if typ_type[0] != idaapi.BT_FUNC:
        #    #not positive that the first type value has to be BT_FUNC or not...
        #    # and whether it's important to only apply to funcs or not
        #    logger.debug('Found named type, but not a function: %s', funcname)
        #    return
        #type_arr = ctypes.create_string_buffer(0x400)
        #type_arr[0] = chr(idaapi.BT_PTR)
        #manualTypeCopy(type_arr, 1, len(type_arr), typ_type)
        #name_buffer = ctypes.create_string_buffer(0x400)
        #print_type_to_one_line(
        #    name_buffer, 
        #    len(name_buffer),
        #    long(til.this),
        #    typ_type,
        #    funcname,
        #    typ_cmt,
        #    typ_fields,
        #    typ_fieldcmts
        #)
        #logger.info('Found type: %s', name_buffer.value)
        ########################################
        #this works as well, but it's deprecated
        #logger.info('Trying to set type: %s', name_buffer.value)
        #ret = g_dll.apply_callee_type(
        #    ctypes.c_uint(here),
        #    type_arr,
        #    typ_fields
        #)
        tinfo = idaapi.tinfo_t()
        #logger.info('Trying to deserialize stuff')
        #logger.info('Type of til: %s', type(til))
        #logger.info('Type of typ_type: %s', type(typ_type))
        ret = g_dll.deserialize_tinfo(
            int(tinfo.this),
            int(til.this), 
            ctypes.byref(typ_type), 
            ctypes.byref(typ_fields),
            ctypes.byref(typ_fieldcmts)
        )
        return tinfo


    def convertUserType(self, stin):
        #get rid of param type macros ida can't parse
        for sub in MSDN_MACROS:
            stin = stin.replace(sub, '')
        return stin

    def run(self):
        logger.debug('Starting up')
        try:
            here = idc.here()
            logger.info('Using ea: 0x%08x', here)
            if using_ida7api:
                mnem = idc.print_insn_mnem(here)
            else:
                mnem =  idc.print_insn_mnem(here)
            if not mnem.startswith('call'):
                logger.info('Not running at a call instruction. Bailing out now')
                return

            if using_ida7api:
                optype = idc.get_operand_type(here, 0) 
            else:
                optype = idc.get_operand_type(here, 0) 
            if optype == idc.o_near:
                logger.info("Cannot (or shouldn't) run when call optype is o_near")
                return

            dlg = ApplyCalleeTypeWidget()
            oldTo = idaapi.set_script_timeout(0)
            res = dlg.exec_()
            idaapi.set_script_timeout(oldTo)

            if res == QtWidgets.QDialog.Accepted:
                logger.debug('Dialog accepted. Input type: %d', dlg.inputType)
            else:
                logger.debug('Dialog rejected')
                return

            tinfo = None
            #check user input type
            if dlg.inputType == dlg.USER_TYPE:
                decl = self.convertUserType(str(dlg.getUserText()))
                tinfo = self.getUserDeclType(decl)
            elif dlg.inputType == dlg.STANDARD_TYPE:
                tinfo = self.getBuiltinGlobalType()
            elif dlg.inputType == dlg.LOCAL_TYPE:
                tinfo = self.getLocalType()
            else:
                logger.info('Bad user input type')
                return
            if tinfo is None:
                logger.debug('Bailing due to null tinfo')
                return
            #logger.info('Deserialize result: %r', ret)
            #not 100% sure if i need to explicitly convert from func to funcptr - seemed
            # to pretty much work without this, but doing it just to be sure
            if not tinfo.is_funcptr():
                logger.debug('Converting to func pointer')
                tinfo.create_ptr(tinfo)
            typename = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, tinfo, '', '')
            logger.info('Applying tinfo: "%s"', str(typename))
            #both applying callee type & setting op type -> not sure if both are needed?
            # set op type causes change in hexrays decompilation
            # apply callee type updates ida's stack analysis
            ret = idaapi.apply_callee_tinfo(here, tinfo)
            if using_ida7api:
                ret = idaapi.set_op_tinfo(here, 0, tinfo)
            else:
                ret = idaapi.set_op_tinfo2(here, 0, tinfo)
            logger.debug('set_op_tinfo2 result: %r', ret)

        except Exception as err:
            logger.exception("Exception caught: %s", str(err))

class ApplyCalleeTypeWidget(QtWidgets.QDialog):
    UNKNOWN_TYPE    = 0
    USER_TYPE       = 1
    STANDARD_TYPE   = 2
    LOCAL_TYPE      = 3

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        try:
            self.tinfo = None
            self.inputType = self.USER_TYPE
            logger.debug('ApplyCalleeTypeWidge starting up')
            self.ui = Ui_ApplyCalleeDialog()
            self.ui.setupUi(self)
            self.ui.te_userTypeText.setTabChangesFocus(True)
            self.ui.pb_useStandardType.clicked.connect(self.onStandardPress)
            self.ui.pb_useLocalType.clicked.connect(self.onLocalPress)
        except Exception as err:
            logger.exception('Error during init: %s', str(err))
    
    def getUserText(self):
        return self.ui.te_userTypeText.toPlainText()

    def onLocalPress(self):
        logger.debug('LOCAL_TYPE')
        self.inputType = self.LOCAL_TYPE
        self.accept()

    def onStandardPress(self):
        logger.debug('STANDARD_TYPE')
        self.inputType = self.STANDARD_TYPE
        self.accept()


def main():
    try:
        global logger
        #logger = jayutils.configLogger(__name__, logging.DEBUG)
        logger = jayutils.configLogger(__name__, logging.INFO)
        launcher = ApplyCalleeTypeRunner()
        launcher.run()
    except Exception as err:
        import traceback
        print(('Error in act: %s: %s' % (str(err), traceback.format_exc())))

if __name__ == '__main__':
    main()

