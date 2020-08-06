#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
# 
########################################################################
# Copyright 2014 Mandiant/FireEye
# Copyright 2019 FireEye
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

idaapi.require('flare')
idaapi.require('flare.apply_callee_type')
idaapi.require('flare.jayutils')

PLUGIN_HELP = "This is help"
PLUGIN_NAME = "ApplyCalleeType"
PREFERRED_SHORTCUT = "Alt-J"
PLUGIN_COMMENT = "Apply callee type to indirect call location"
ACTION_NAME = 'flare:apply_callee_type'
MENU_PATH = "Edit/Operand type/Manual"

# get the IDA version number
ida_major, ida_minor = list(map(int, idaapi.get_kernel_version().split(".")))
using_ida7api = (ida_major > 6)

ex_addmenu_item_ctx = None 

def installMenuIda7():
    class ApplyCalleeHandler(idaapi.action_handler_t):
        def activate(self, ctx):
            doApplyCallee()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET

    ret = idaapi.register_action(idaapi.action_desc_t(
            ACTION_NAME,            # Name. Acts as an ID. Must be unique.
            PLUGIN_NAME,            # Label. That's what users see.
            ApplyCalleeHandler(),   # Handler. Called when activated, and for updating
            PREFERRED_SHORTCUT,     # Shortcut (optional)
            PLUGIN_COMMENT          # Tooltip (optional)
            ))
    if not ret:
        print('Failed to register action. Bailing out')
        return
    # Insert the action in the menu
    if idaapi.attach_action_to_menu(MENU_PATH, ACTION_NAME, idaapi.SETMENU_APP):
        print("Attached to menu.")
    else:
        print("Failed attaching to menu.")

    setattr(sys.modules['idaapi'], '_apply_callee_type_plugin_installFlag', True)

def installMenu():
    #hack -> stashing a flag under idaapi to prevent multiple menu items from appearing
    if hasattr(sys.modules['idaapi'], '_apply_callee_type_plugin_installFlag'):
        #print('Skipping menu install: already present')
        return
    if using_ida7api:
        return installMenuIda7()
    global ex_addmenu_item_ctx
    ex_addmenu_item_ctx = idaapi.add_menu_item(
        MENU_PATH, 
        PLUGIN_NAME, 
        PREFERRED_SHORTCUT, 
        0, 
        doApplyCallee, 
        tuple("hello world")
    )
    if ex_addmenu_item_ctx  is None:
        print('Failed to init apply_callee_type_plugin')

    setattr(sys.modules['idaapi'], '_apply_callee_type_plugin_installFlag', True)


class apply_callee_type_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""


    def init(self):
        idaapi.msg('apply_callee_type_plugin:init\n')

        installMenu()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        #idaapi.msg('apply_callee_type_plugin:run\n')
        flare.apply_callee_type.main()

    def term(self):
        #idaapi.msg('apply_callee_type_plugin:term\n')
        #if self.ex_addmenu_item_ctx is not None:
        #    idaapi.del_menu_item(ex_addmenu_item_ctx)
        pass

def PLUGIN_ENTRY():
    try:
        return apply_callee_type_plugin_t()
    except Exception as err:
        import traceback
        msg("Error: %s\n%s" % (str(err), traceback.format_exc()))
        raise

def doApplyCallee(*args):
    #idaapi.msg('doApplyCallee:Calling now\n')
    flare.apply_callee_type.main()

