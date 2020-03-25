# -*- coding: utf-8 -*-
# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""IDA utils by @mykill"""

import idc
import ida_ua
import idaapi
import idautils
import ida_kernwin

import binascii
import logging
import numbers
from collections import namedtuple

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2019 FireEye, Inc.'
__license__ = 'Apache License 2.0'
__version__ = '1.0'

###############################################################################
# Initialization
###############################################################################

logger = logging.getLogger(__name__)

###############################################################################
# Useful tidbits
###############################################################################


def phex(n):
    """Pretty hex.

    The `hex()` function can append a trailing 'L' signifying the long
    datatype. Stripping the trailing 'L' does two things:
    1. Can double click it in the IDA output window to jump to that address
    2. Looks cleaner

    Args:
        n (numbers.Integral): Number to prettify

    Returns:
        Hex string for `n` without trailing 'L'
    """
    return hex(n).rstrip('L')


def align(n, a):
    """Align @n to @a bytes.

    Examples:
        align(4, 4) = 4
        align(3, 4) = 4
        align(0, 4) = 0
        align(5, 4) = 8

    Args:
        n (numbers.Integral): Virtual address to align
        a (numbers.Integral): Alignment

    Returns:
        New, aligned address, or @n if already @a-byte aligned.
    """
    return (n + (a - 1)) & ~(a - 1)


def get_bitness():
    """Get the architecture bit width of this IDB."""
    inf = idaapi.get_inf_structure()
    return 64 if inf.is_64bit() else 32 if inf.is_32bit() else 16


def makename_safe(va, nm, max_tries=10):
    """Attempt to name @va as @nm appending numbers up to @max_tries.

    Appends _0, _1, etc. until successful or bails after the specified number
    of tries.

    Args:
        va (numbers.Integral): Virtual address to name.
        nm (str): Name to apply
        max_tries (numbers.Integral): Number of times to retry naming while
            appending successive increasing number suffices

    Returns:
        True if successful else False
    """
    if not all([va, nm]):
        raise ValueError('makename_safe requires both va and nm args')

    successful = False
    tryname = nm
    for i in range(max_tries):
        if idc.set_name(va, tryname, idc.SN_NOWARN):
            successful = True
            break
        tryname = '%s_%d' % (nm, i)

    if not successful:
        logger.error('Looped %d times and failed to name %s as %s(_N)' %
              (max_tries, phex(va), nm))

    return successful


def for_each_call_to(callback, va=None):
    """For each xref to va that is a call, pass xref va to callback.

    Falls back to highlighted identifier or current location if va is
    unspecified.
    """
    if not va:
        v = ida_kernwin.get_current_viewer()
        hi = ida_kernwin.get_highlight(v)
        if hi and hi[1]:
            nm = hi[0]
            va = idc.get_name_ea_simple(nm)
            if va >= idaapi.cvar.inf.maxEA:
                va = None

    va = va or idc.here()

    # Obtain and de-duplicate addresses of xrefs that are calls
    callsites = set([x.frm for x in idautils.XrefsTo(va)
                     if idc.print_insn_mnem(x.frm) == 'call'])
    for va in callsites:
        callback(va)


# Instruction operand specification.
#
# Operand types are from ida_ua.o_* e.g. o_reg, o_mem.
# >>> {x: getattr(ida_ua, x) for x in dir(ida_ua) if x.startswith('o_')}
#
# Quick ref:
#   ida_ua.o_reg ==      1: "General Register (al,ax,es,ds...)",
#   ida_ua.o_mem ==      2: "Memory Reference",
#   ida_ua.o_phrase ==   3: "Base + Index",
#   ida_ua.o_displ ==    4: "Base + Index + Displacement",
#   ida_ua.o_imm ==      5: "Immediate",
#   ida_ua.o_far ==      6: "Immediate Far Address",
#   ida_ua.o_near ==     7: "Immediate Near Address",
#   ida_ua.o_idpspec0 == 8: "FPP register",
#   ida_ua.o_idpspec1 == 9: "386 control register",
#   ida_ua.o_idpspec2 == 10: "386 debug register",
#   ida_ua.o_idpspec3 == 11: "386 trace register",
OpSpec = namedtuple('OpSpec', 'pos type name')


def find_instr(va_start, direction, mnems=None, op_specs=[], max_instrs=0):
    """Find an instruction in the current function conforming to the
    specified mnemonics/operands.

    Args:
        va_start (numbers.Integral): Virtual address from whence to begin
            search.
        direction (str): Direction in assembly listing to proceed with search.
            Valid directions are 'up' or 'down'.
        mnems (str or iterable of str): Optional assembly language mnemonic(s)
            to search for.
        op_specs (iterable of OpSpec): Iterable containing OpSpec operand
            specifications.
        max_instrs (numbers.Integral): Number of instructions to search before
            returning None.

    Returns:
        Virtual address where instruction was found
        None if not applicable

    The search begins at the next instruction above or below the specified
    virtual address.

    Notably, upward search scans *decreasing* addresses because the direction
    is with respect to the assembly listing as it appears on the screen, not
    addresses in memory.

    You must specify either one or more mnemonics, or one or more operand
    specifications.

    If max_instrs is left as the default value of zero, this function will scan
    9999 instructions or to the start/end of the function, whichever is first.
    """
    if va_start and (not isinstance(va_start, numbers.Integral)):
        raise ValueError('Invalid va_start')

    va = va_start or idc.here()

    if not max_instrs:
        max_instrs = 9999

    if direction.lower() in ('up', 'back', 'backward', 'previous', 'prev'):
        iterate = idaapi.prev_head
        va_stop = idc.get_func_attr(va, idc.FUNCATTR_START)
        if va_stop == idc.BADADDR:
            va_stop = 0
    elif direction.lower() in ('down', 'forward', 'next'):
        iterate = idaapi.next_head
        va_stop = idc.get_func_attr(va, idc.FUNCATTR_END)
    else:
        raise ValueError('Invalid direction')

    for count in xrange(max_instrs):
        va = iterate(va, va_stop)

        if is_conformant_instr(va, mnems, op_specs):
            return va

        if va in (0, idc.BADADDR):
            break

    return None


def is_conformant_instr(va, mnems, op_specs):
    """Check if instruction at @va conforms to operand specifications list.

    Args:
        va (numbers.Integral): Virtual address of instruction to assess.
        mnems (str or iterable of str): Optional instruction mnemonic(s) to
            check for.
        op_specs (iterable of OpSpec): Iterable containing zero or more operand
            specification tuples (operand position, type, and name).

    Returns:
        True if conformant
        False if nonconformant
    """
    if (not mnems) and (not op_specs):
        msg = 'Must specify either a mnemonic or an operand specification list'
        raise ValueError(msg)

    mnem_current = idc.print_insn_mnem(va)
    if mnems:
        if isinstance(mnems, basestring):
            if mnem_current != mnems:
                return False
        else:
            if mnem_current not in mnems:
                return False

    for spec in op_specs:
        if not is_conformant_operand(va, spec):
            return False

    return True


def is_conformant_operand(va, op_spec):
    """Check that operand conforms to specification.

    Args:
        va (numbers.Integral): Virtual address of instruction to assess.
        op_spec (OpSpec): Operand specification tuple (operand position, type,
            and name)

    Returns:
        True if conformant
        False if nonconformant
    """
    spec = OpSpec(*op_spec)  # Make it convenient to pass plain tuples

    if (spec.pos is None) or ((not spec.name) and (not spec.type)):
        msg = 'Must specify an operand position and either a name or type'
        raise ValueError(msg)

    if spec.type is not None and idc.get_operand_type(va, spec.pos) != spec.type:
        return False

    if spec.name is not None:
        # For two types:
        #   o_phrase = 3 Base + Index
        #   o_displ =  4 Base + Index + Displacement
        # Use substring matching to compensate for IDA Pro's representation
        if spec.type in (ida_ua.o_phrase, ida_ua.o_displ):
            if spec.name not in idc.print_operand(va, spec.pos):
                return False

        # For these types:
        #   o_imm =  5   Immediate
        #   o_far =  6   Immediate Far Address
        #   o_near = 7   Immediate Near Address
        # Check both address and name
        elif spec.type in (ida_ua.o_imm, ida_ua.o_far, ida_ua.o_near):
            if isinstance(spec.name, basestring):
                if idc.print_operand(va, spec.pos) != spec.name:
                    return False
            elif idc.get_operand_value(va, spec.pos) != spec.name:
                return False
        else:
            if idc.print_operand(va, spec.pos) != spec.name:
                return False

    return True


###############################################################################
# Code Carving i.e. function extraction
###############################################################################
# Why:
# * To extract whole funtions for emulation, shellcode crafting, or other
#   external processing.
# * To extend Code Grafting by adding function opcodes to the library already
#   present there.
#
# Code Grafting allows you to graft static implementations of imported
# functions into your IDB for purposes of emulation in Bochs IDB mode or by
# other emulators. For instructions on adding synthetic import implementations
# to the Code Grafting library for use with your binary, see `code_grafter.py`.


def emit_fnbytes_ascii(fva=None, warn=True):
    """Emit function bytes as an ASCII hexlified string.

    Args:
        fva (numbers.Integral): function virtual address.
            Defaults to here() if that is the start of a function, else
            defaults to the start of the function that here() is a part of.
        warn (bool): enable interactive warnings

    Returns:
        str: ASCII hexlified string of instruction opcode bytes for function.
    """
    header = ''
    footer = ''
    indent = ''

    def _emit_instr_ascii(va, the_bytes, size):
        return binascii.hexlify(the_bytes)

    return _emit_fnbytes(_emit_instr_ascii, header, footer, indent, fva, warn)


def emit_fnbytes_python(fva=None, warn=True):
    """Emit function bytes as Python code with disassembly in comments.

    Args:
        fva (numbers.Integral): function virtual address.
            Defaults to here() if that is the start of a function, else
            defaults to the start of the function that here() is a part of.
        warn (bool): enable interactive warnings

    Returns:
        str: Python code you can spruce up and paste into a script.
    """
    header = 'instrs_{name} = (\n'
    footer = ')'
    indent = '    '

    def _emit_instr_python(va, the_bytes, size):
        disas = idc.GetDisasm(va)
        return "'%s' # %s\n" % (binascii.hexlify(the_bytes), disas)

    return _emit_fnbytes(_emit_instr_python, header, footer, indent, fva, warn)


def emit_fnbytes_c(fva=None, warn=True):
    """Emit function bytes as C code with disassembly in comments.

    Args:
        fva (numbers.Integral): function virtual address.
            Defaults to here() if that is the start of a function, else
            defaults to the start of the function that here() is a part of.
        warn (bool): enable interactive warnings

    Returns:
        str: C code you can spruce up and paste into a script.
    """

    header = 'unsigned char *instrs_{name} = {{\n'
    footer = '};'
    indent = '\t'

    def _emit_instr_for_c(va, the_bytes, size):
        disas = idc.GetDisasm(va)
        buf = ''.join(['\\x%s' % (binascii.hexlify(c)) for c in the_bytes])
        return '"%s" /* %s */\n' % (buf, disas)

    return _emit_fnbytes(_emit_instr_for_c, header, footer, indent, fva, warn)


def _emit_fnbytes(emit_instr_cb, header, footer, indent, fva=None, warn=True):
    """Emit function bytes in a format defined by the callback and
    headers/footers provided.

    Warns if any instruction operands are not consistent with
    position-independent code, in which case the user may need to templatize
    the position-dependent portions.
    """
    fva = fva or idc.here()
    fva = idc.get_func_attr(fva, idc.FUNCATTR_START)
    va_end = idc.get_func_attr(fva, idc.FUNCATTR_END)

    # Operand types observed in position-independent code:
    optypes_position_independent = set([
        ida_ua.o_reg,       # 1: General Register (al,ax,es,ds...)
        ida_ua.o_phrase,    # 3: Base + Index
        ida_ua.o_displ,     # 4: Base + Index + Displacement
        ida_ua.o_imm,       # 5: Immediate
        ida_ua.o_near,      # 7: Immediate Near Address
    ])

    # Notably missing because I want to note and handle these if/as they are
    # encountered:
    # ida_ua.o_idpspec0 = 8: FPP register
    # ida_ua.o_idpspec1 = 9: 386 control register
    # ida_ua.o_idpspec2 = 10: 386 debug register
    # ida_ua.o_idpspec3 = 11: 386 trace register

    va = fva
    nm = idc.get_name(fva)
    optypes_found = set()
    s = header.format(name=nm)
    while va not in (va_end, idc.BADADDR):
        size = idc.get_item_size(va)
        the_bytes = idc.get_bytes(va, size)

        for i in range(0, 8):
            optype = idc.get_operand_type(va, i)
            if optype:
                optypes_found.add(optype)

        s += indent + emit_instr_cb(va, the_bytes, size)
        va = idc.next_head(va)
    s += footer

    position_dependent = optypes_found - optypes_position_independent
    if position_dependent:
        msg = ('This code may have position-dependent operands (optype %s)' %
               (', '.join([str(o) for o in position_dependent])))
        if warn:
            Warning(msg)
        else:
            logger.warn(msg)

    return s



