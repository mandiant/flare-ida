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
# Find calls to GetProcAddress and rename the global variables
# storing a pointer to the resolved APIs

import idc
import idaapi

'''
    Ctree's subtree (for reference)

    cot_asg
    /     \
   /       \
cot_obj  cot_cast    
            |
         cot_call
         /   |   \
        /    |    \
       /     |     \
      /      |      \
 cot_obj  cot_var  cot_obj
'''

def findGetProcAddress(cfunc):
    class visitor(idaapi.ctree_visitor_t):
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
            self.cfunc = cfunc

        def visit_expr(self, i):
            if i.op == idaapi.cot_call:
                # look for calls to GetProcAddress
                if idc.Name(i.x.obj_ea) == "GetProcAddress":

                    # ASCSTR_C == 0
                    # Check to see if the second argument is a C string
                    if idc.GetStringType(i.a[1].obj_ea) == 0:
                        targetName = idc.GetString(i.a[1].obj_ea, -1, 0)

                        # Found function name
                        # Look for global assignment
                        parent = self.cfunc.body.find_parent_of(i)
                        if parent.op == idaapi.cot_cast:
                            # Ignore casts and look for the parent
                            parent = self.cfunc.body.find_parent_of(parent)

                        if parent.op == idaapi.cot_asg:
                            # We want to find the left hand side (x)
                            idc.MakeName(parent.cexpr.x.obj_ea, targetName + "_")

            return 0
    
    v = visitor(cfunc)
    v.apply_to(cfunc.body, None)

def event_callback(event, *args):
        if event == idaapi.hxe_maturity:
            cfunc, maturity = args
            if maturity == idaapi.CMAT_FINAL:
                findGetProcAddress(cfunc)

        return 0

def main():
    if not idaapi.init_hexrays_plugin():
        return False

    print "Hex-rays version %s has been detected" % idaapi.get_hexrays_version()
    idaapi.install_hexrays_callback(event_callback)


if main():
    idaapi.term_hexrays_plugin();
