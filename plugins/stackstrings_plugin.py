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
# IDA Plugin wrapper for stack strings search
#
########################################################################


import logging

import idc 
import idautils  
import idaapi


class stackstrings_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "StackStrings"
    wanted_hotkey = "Alt-0"

    def init(self):
        try:
            idaapi.msg("StackStrings init() called!\n")
            return idaapi.PLUGIN_OK
        except Exception, err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        
        return idaapi.PLUGIN_SKIP


    def run(self, arg):
        try:
            idaapi.msg("StackStrings run() called with %d!\n" % arg)
            idaapi.require('flare')
            idaapi.require('flare.stackstrings')
            flare.stackstrings.main()
            idaapi.msg("StackStrings run() done")
        except Exception, err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise
            
        idaapi.msg("StackStrings run() complete!\n")

    def term(self):
        idaapi.msg("StackStrings term() called!\n")

def PLUGIN_ENTRY():
    return stackstrings_plugin_t()


