# Find calls to GetProcAddress and rename global variables
import idc
import idaapi
'''
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
            if (i.op == idaapi.cot_call):
                    # look for calls to GetProcAddress
                    if (idc.Name(i.x.obj_ea) == "GetProcAddress"):

                        # ASCSTR_C == 0
                        # check to see if the second argument is a c string
                        if (idc.GetStringType(i.a[1].obj_ea) == 0):
                            targetName = idc.GetString(i.a[1].obj_ea, -1, 0)
                            #print "GetProcAdderss for: %s" % (targetName)

                            ## found function name
                            ## look for global assignment
                            parent = self.cfunc.body.find_parent_of(i)
                            print "Parent type: %s" % parent.op
                            if (parent.op == idaapi.cot_cast):
                                # ignore casts and look for the parent
                                parent = self.cfunc.body.find_parent_of(parent)
                                print "Parent Parent type: %s" % parent.op

                            if (parent.op == idaapi.cot_asg):
                                # we want to find the left hand side
                                print "Left Side %s %s" % (parent.cexpr.x.opname, hex(parent.cexpr.x.obj_ea))
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
'''
    f = idaapi.get_func(idaapi.get_screen_ea());
    if f is None:
        print "Please position the cursor within a function"
        return True

    cfunc = idaapi.decompile(f);
    if cfunc is None:
        print "Failed to decompile!"
        return True
    print "Decompiled function"
'''
if main():
    idaapi.term_hexrays_plugin();
