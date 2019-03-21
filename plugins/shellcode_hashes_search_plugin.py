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
# IDA Plugin wrapper for shellcode hash search.
#
########################################################################


import idc 
import idautils  
import idaapi

idaapi.require('flare')
idaapi.require('flare.shellcode_hash_search')

class shellcode_search_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "Shellcode Hashes"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        flare.shellcode_hash_search.main()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return shellcode_search_plugin_t()



