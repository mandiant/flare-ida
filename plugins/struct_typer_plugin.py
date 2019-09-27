#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2013 Mandiant
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
# IDA Plugin wrapper for struct typer script.
#
########################################################################


import idc 
import idautils  
import idaapi

idaapi.require('flare')
idaapi.require('flare.struct_typer')

class struct_typer_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "StructTyper"
    wanted_hotkey = ""

    def init(self):
        #idaapi.msg("StructTyper init() called!\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        #idaapi.msg("StructTyper run() called with %d!\n" % arg)
        flare.struct_typer.main()

    def term(self):
        #idaapi.msg("StructTyper term() called!\n")
        pass

def PLUGIN_ENTRY():
    return struct_typer_plugin_t()



