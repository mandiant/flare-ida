#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2014 FireEye
# Copyright 2019 FireEye
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
# IDA Plugin wrapper for stack strings search
#
########################################################################


import sys
import logging

import idc 
import idautils  
import idaapi

is_py2 = (sys.version_info[0] == 2)

if is_py2:
    # currently depending on vivisect, which will never be ported to py3
    idaapi.require('flare')
    idaapi.require('flare.stackstrings')

PLUGIN_COMMENT = "This is a comment"
PLUGIN_HELP = "This is help"
PLUGIN_NAME = "StackStrings"
PLUGIN_WANTED_HOTKEY = "Alt-0"

# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (ida_major > 6)
ex_addmenu_item_ctx = None 


class stackstrings_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def init(self):
        try:
            idaapi.msg("StackStrings init() called!\n")
            return idaapi.PLUGIN_OK
        except Exception as err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            idaapi.msg("StackStrings run() called with %d!\n" % arg)
            if is_py2:
                flare.stackstrings.main()
                idaapi.msg("StackStrings run() done")
            else:
                idaapi.msg("WARNING: stackstrings only works under python2 due to vivisect dependency\n")
        except Exception as err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise
            
        idaapi.msg("StackStrings run() complete!\n")

    def term(self):
        idaapi.msg("StackStrings term() called!\n")

def PLUGIN_ENTRY():
    return stackstrings_plugin_t()


