########################################################################
# Copyright 2018 FireEye
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
# Stack strings helper
# IDA's decompiler view shows stack strings in numerical form, a format highly unreadable.
# This script adds a popup menu entry to display them as characters, to quickly skim through them
#
# Tested with IDA 7+
#

import ida_hexrays
import ida_kernwin
import idaapi

import string


ACTION_NAME = "Stack strings"

# --------------------------------------------------------------------------
class char_converter_visitor_t(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

    def visit_expr(self, expr):
        """
        Search for simple assignents to stack vars
        """
        if expr.op != ida_hexrays.cot_asg:
            return 0

        _x = expr.x
        _y = expr.y

        if _x.op == ida_hexrays.cot_var and _y.op == ida_hexrays.cot_num:
            # Something like "v1 = 65"
            num_value = _y.n.value(_y.type)

            # Bail out soon
            if num_value < 1 or num_value > 255:
                return 0

            if chr(num_value) not in string.printable:
                return 0

            # Create a new expr object to replace _y
            # This will be of type cot_str
            z = idaapi.cexpr_t()

            # In order to modify an existing cexpr
            # you have to swap it with a newly created one
            z.swap(_y)
            _y.op = ida_hexrays.cot_str
            _y.string = chr(num_value)

        return 0

# --------------------------------------------------------------------------
class stack_strings_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        # ----------------------------------------------
        # Do something with the vdui (vu)
        print "Analyzing decompiled code..."
        cv = char_converter_visitor_t()
        cv.apply_to(vu.cfunc.body, None)
        
        vu.refresh_ctext()
        
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

def cb(event, *args):
    if event == ida_hexrays.hxe_populating_popup:
        widget, phandle, vu = args
        res = idaapi.attach_action_to_popup(vu.ct, None, ACTION_NAME)

    return 0


def show_banner():
    print "-" * 60
    print "CHAR CONVERTER"
    print "Converts stack string assignments to char representation"
    print
    print "Example:"
    print "v1 = 65 -> v1 = 'A'"
    print "v2 = 66 -> v1 = 'B'"
    print "..."
    print "-" * 60


def main():
    show_banner()

    print "Unregistering old action..."
    ida_kernwin.unregister_action(ACTION_NAME)

    if ida_hexrays.init_hexrays_plugin():
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_NAME,
                "Keep sanity (stack strings)",
                stack_strings_ah_t(),
                None))

        print "Registered new action"

        idaapi.install_hexrays_callback(cb)

    else:
        print "[x] No decompiler found!"
        return



if __name__ == '__main__':
    main()

