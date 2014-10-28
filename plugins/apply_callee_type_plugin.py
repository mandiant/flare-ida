#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
# 
########################################################################
# Copyright 2014 Mandiant/FireEye
#
# Mandiant/Fireye licenses this file to you under the Apache License, Version
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

import sys

import idc 
import idautils  
import idaapi

class apply_callee_type_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = "Apply callee type to indirect call location"

    help = "This is help"
    wanted_name = "ApplyCalleeType"
    wanted_hotkey = "Alt-J"

    def init(self):
        idaapi.msg('apply_callee_type_plugin:init\n')
        idaapi.require('flare')
        idaapi.require('flare.apply_callee_type')
        idaapi.require('flare.jayutils')

        #hack -> stashing a flag under idaapi to prevent multiple menu items from appearing
        if hasattr(sys.modules['idaapi'], '_apply_callee_type_plugin_installFlag'):
            #print 'Skipping menu install: already present'
            pass
        else:
            self.ex_addmenu_item_ctx = idaapi.add_menu_item(
                "Edit/Operand type/Manual", 
                "ApplyCalleeType", 
                "Alt-J", 
                0, 
                doApplyCallee, 
                tuple("hello world")
            )
            if self.ex_addmenu_item_ctx  is None:
                print 'Failed to init apply_callee_type_plugin'

            setattr(sys.modules['idaapi'], '_apply_callee_type_plugin_installFlag', True)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg('apply_callee_type_plugin:run\n')
        flare.apply_callee_type.main()

    def term(self):
        idaapi.msg('apply_callee_type_plugin:term\n')
        #if self.ex_addmenu_item_ctx is not None:
        #    idaapi.del_menu_item(ex_addmenu_item_ctx)

def PLUGIN_ENTRY():
    return apply_callee_type_plugin_t()

def doApplyCallee(*args):
    #idaapi.msg('doApplyCallee:Calling now\n')
    flare.apply_callee_type.main()

