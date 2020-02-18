# -*- coding: utf-8 -*-
# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""Code grafting: Static linking of code into IDBs to aid emulation."""

import idc
import idaapi
import idautils
import ida_xref
import ida_bytes

import mykutils
from mykutils import phex
from seghelper import SegPlanner

import struct
import logging
import binascii

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2019 FireEye, Inc.'
__license__ = 'Apache License 2.0'
__version__ = '1.0'

logger = logging.getLogger()
logging.basicConfig(format='%(message)s', level=logging.INFO)

###############################################################################
# Constants
###############################################################################
METAPC = 'metapc'

###############################################################################
# Globals
###############################################################################

# Code Carving/Grafting

g_seg_sig_code_grafter = 'Segment added by FLARE Code Grafter'
g_patched_call_cmt = 'Patched for emulation, was:'
g_cmt_pointed = '(Pointed'

# Name tuple -> implementation lookup
g_patch_pointer_width = {
    32: idc.patch_dword,
    64: idc.patch_qword,
}

# Per-architecture/bitness library of native function implementations. Each
# entry is a hexadecimal ASCII string of native opcodes compiled from C and
# specially crafted not to access globals or call other functions.
g_fnbytes = {
    METAPC: {
        32: {},
        64: {},
    }
}

g_fnbytes[METAPC][32]['memcpy'] = (
    '558bec83ec088b45088945f88b4d0c894dfc8b55108b451083e80189451085d2'
    '741e8b4df88b55fc8a0288018b4df883c101894df88b55fc83c2018955fcebd2'
    '8b45088be55dc3'
    )
g_fnbytes[METAPC][64]['memcpy'] = (
    '4c89442418488954241048894c24084883ec18488b4424204889442408488b44'
    '242848890424488b4c2430488b4424304883e80148894424304885c9742a488b'
    '4c2408488b04240fb6008801488b4424084883c0014889442408488b04244883'
    'c00148890424ebbe488b4424204883c418c3'
    )

g_fnbytes[METAPC][32]['memset'] = (
    '558bec518b45088945fc8b4d108b551083ea0189551085c974138b45fc8a4d0c'
    '88088b55fc83c2018955fcebdd8b45088be55dc3'
    )
g_fnbytes[METAPC][64]['memset'] = (
    '4c894424188954241048894c24084883ec18488b44242048890424488b4c2430'
    '488b4424304883e80148894424304885c97419488b0c240fb64424288801488b'
    '04244883c00148890424ebcf488b4424204883c418c3'
    )

g_fnbytes[METAPC][32]['strcpy'] = (
    '558bec518b45088945fc8b4dfc8b550c8a0288018b4dfc0fbe118b45fc83c001'
    '8945fc8b4d0c83c101894d0c85d27402ebd88b45088be55dc3'
    )
g_fnbytes[METAPC][64]['strcpy'] = (
    '488954241048894c24084883ec18488b44242048890424488b0c24488b442428'
    '0fb6008801488b04240fbe08488b04244883c00148890424488b4424284883c0'
    '01488944242885c97402ebcb488b4424204883c418c3'
    )

g_strlen_metapc_32bit = (
    '558bec51c745fc000000008b45080fbe088b550883c20189550885c9740b8b45'
    'fc83c0018945fcebe28b45fc8be55dc3'
    )
g_strlen_metapc_64bit = (
    '48894c24084883ec1848c7042400000000488b4424200fbe08488b4424204883'
    'c001488944242085c9740e488b04244883c00148890424ebd8488b04244883c4'
    '18c3'
    )

# Covers lstrlenA
g_fnbytes[METAPC][32]['strlen'] = g_strlen_metapc_32bit
g_fnbytes[METAPC][64]['strlen'] = g_strlen_metapc_64bit

# return "en-US";
g_fnbytes[METAPC][32]['setlocale'] = 'e8000000005883c007c20800' + '656e2d5553'
g_fnbytes[METAPC][64]['setlocale'] = '488b0501000000c3' + '656e2d5553'
g_fnbytes[METAPC][32]['wsetlocale'] = ('e8000000005883c007c20800' +
                                       '65006e002d0055005300')
g_fnbytes[METAPC][64]['wsetlocale'] = ('488b0501000000c3' +
                                       '65006e002d0055005300')

g_retn0_metapc_64bit = '4831c0c3'
g_retn1_metapc_64bit = '4831c04883c001c3'

g_fnbytes[METAPC][32]['retn0'] = '31c0c3'
g_fnbytes[METAPC][64]['retn0'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn0_1arg'] = '31c0c20400'
g_fnbytes[METAPC][64]['retn0_1arg'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn0_3arg'] = '31c0c20C00'
g_fnbytes[METAPC][64]['retn0_3arg'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn1'] = '31c040c3'
g_fnbytes[METAPC][64]['retn1'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_1arg'] = '31c040c20400'
g_fnbytes[METAPC][64]['retn1_1arg'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_2arg'] = '31c040c20800'
g_fnbytes[METAPC][64]['retn1_2arg'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_6arg'] = '31c040c21800'
g_fnbytes[METAPC][64]['retn1_6arg'] = g_retn1_metapc_64bit


# Allocator => All names it is known by
g_allocators_aliases = {
    'malloc': ('??2@YAPAXI@Z', '_malloc', 'malloc',),
    'HeapAlloc': ('HeapAlloc',),
    'VirtualAlloc': ('VirtualAlloc',),
}

# Memory allocation templates cannot be handled as simply as static functions
# can be, because they must access global data. Furthermore, these are all
# basically the same allocator but they have different signatures.
g_fnbytes_allocators = {
    METAPC: {
        32: {},
        64: {},
    }
}

# Main differences among allocator implementations:
#   * [ebp+size] is different per argument layout
#   * cdecl (malloc) and various stdcall (HeapAlloc/VirtualAlloc) return
#     opcodes
# Violating D.R.Y. to make it clear how to add these, make them work, and
# maintain them.
g_fnbytes_allocators[METAPC][32]['malloc'] = (
    '55'                # push    ebp
    '8bec'              # mov     ebp, esp
    '51'                # push    ecx
    'a1{next_}'         # mov     eax, _next
    '05{arena}'         # add     eax, offset _arena
    '8945fc'            # mov     [ebp+ret], eax
    '8b4d08'            # mov     ecx, [ebp+size]
    '8b15{next_}'       # mov     edx, _next
    '8d440aff'          # lea     eax, [edx+ecx-1]
    '0dff0f0000'        # or      eax, 0FFFh
    '83c001'            # add     eax, 1
    'a3{next_}'         # mov     _next, eax
    '8b45fc'            # mov     eax, [ebp+ret]
    '8be5'              # mov     esp, ebp
    '5d'                # pop     ebp
    'c3'                # retn
)
g_fnbytes_allocators[METAPC][64]['malloc'] = (
    '48894c2408'        # mov     [rsp+arg_0], rcx
    '4883ec18'          # sub     rsp, 18h

  # '488d0570cd0100'    # lea     rax, arena        ; Original, RIP-relative
    '48B8{arena}'       # mov     rax, &cs:arena    ; Hand-written, absolute64

  # '48030529bf0100'    # add     rax, cs:next      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute64
    '480301'            # add     rax, [rcx]        ; Hand-written

    '48890424'          # mov     [rsp+18h+var_18], rax

  # '488b0d1ebf0100'    # mov     rcx, cs:next      ; Original, RIP-relative
    '488b09'            # mov     rcx, [rcx]        ; Hand-written, deref &next

    '488b442420'        # mov     rax, [rsp+18h+arg_0]
    '488d4401ff'        # lea     rax, [rcx+rax-1]
    '480dff0f0000'      # or      rax, 0FFFh
    '4883c001'          # add     rax, 1

  # '48890503bf0100'    # mov     cs:next, rax      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute
    '488901'            # mov     [rcx], rax

    '488b0424'          # mov     rax, [rsp+18h+var_18]
    '4883c418'          # add     rsp, 18h
    'c3'                # retn
)

g_fnbytes_allocators[METAPC][32]['HeapAlloc'] = (
    '55'                # push    ebp
    '8bec'              # mov     ebp, esp
    '51'                # push    ecx
    'a1{next_}'         # mov     eax, _next
    '05{arena}'         # add     eax, offset _arena
    '8945fc'            # mov     [ebp+ret], eax
    '8b4d10'            # mov     ecx, [ebp+size]
    '8b15{next_}'       # mov     edx, _next
    '8d440aff'          # lea     eax, [edx+ecx-1]
    '0dff0f0000'        # or      eax, 0FFFh
    '83c001'            # add     eax, 1
    'a3{next_}'         # mov     _next, eax
    '8b45fc'            # mov     eax, [ebp+ret]
    '8be5'              # mov     esp, ebp
    '5d'                # pop     ebp
    'c20c00'            # retn    0Ch
)
g_fnbytes_allocators[METAPC][64]['HeapAlloc'] = (
    '4c89442418'        # mov     [rsp+arg_10], r8
    '89542410'          # mov     [rsp+arg_8], edx
    '48894c2408'        # mov     [rsp+arg_0], rcx
    '4883ec18'          # sub     rsp, 18h

  # '488d0517cd0100'    # lea     rax, arena        ; Original, RIP-relative
    '48B8{arena}'       # mov     rax, &cs:arena    ; Hand-written, absolute64

  # '480305d0be0100'    # add     rax, cs:next      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute64
    '480301'            # add     rax, [rcx]        ; Hand-written

    '48890424'          # mov     [rsp+18h+var_18], rax

  # '488b0dc5be0100'    # mov     rcx, cs:next      ; Original, RIP-relative
    '488b09'            # mov     rcx, [rcx]        ; Hand-written, deref &next

    '488b442430'        # mov     rax, [rsp+18h+arg_10]
    '488d4401ff'        # lea     rax, [rcx+rax-1]
    '480dff0f0000'      # or      rax, 0FFFh
    '4883c001'          # add     rax, 1

  # '488905aabe0100'    # mov     cs:next, rax      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute
    '488901'            # mov     [rcx], rax

    '488b0424'          # mov     rax, [rsp+18h+var_18]
    '4883c418'          # add     rsp, 18h
    'c3'                # retn
)

g_fnbytes_allocators[METAPC][32]['VirtualAlloc'] = (
    '55'                # push    ebp
    '8bec'              # mov     ebp, esp
    '51'                # push    ecx
    'a1{next_}'         # mov     eax, _next
    '05{arena}'         # add     eax, offset _arena
    '8945fc'            # mov     [ebp+ret], eax
    '8b4d0c'            # mov     ecx, [ebp+dwSize]
    '8b15{next_}'       # mov     edx, _next
    '8d440aff'          # lea     eax, [edx+ecx-1]
    '0dff0f0000'        # or      eax, 0FFFh
    '83c001'            # add     eax, 1
    'a3{next_}'         # mov     _next, eax
    '8b45fc'            # mov     eax, [ebp+ret]
    '8be5'              # mov     esp, ebp
    '5d'                # pop     ebp
    'c21000'            # retn    10h
)
g_fnbytes_allocators[METAPC][64]['VirtualAlloc'] = (
    '44894c2420'        # mov     [rsp+arg_18], r9d
    '4489442418'        # mov     [rsp+arg_10], r8d
    '4889542410'        # mov     [rsp+arg_8], rdx
    '48894c2408'        # mov     [rsp+arg_0], rcx
    '4883ec18'          # sub     rsp, 18h

  # '488d05b1cc0100'    # lea     rax, arena        ; Original, RIP-relative
    '48B8{arena}'       # mov     rax, &cs:arena    ; Hand-written, absolute64

  # '4803056abe0100'    # add     rax, cs:next      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute64
    '480301'            # add     rax, [rcx]        ; Hand-written

    '48890424'          # mov     [rsp+18h+var_18], rax

  # '488b0d5fbe0100'    # mov     rcx, cs:next      ; Original, RIP-relative
    '488b09'            # mov     rcx, [rcx]        ; Hand-written, deref &next

    '488b442428'        # mov     rax, [rsp+18h+arg_8]
    '488d4401ff'        # lea     rax, [rcx+rax-1]
    '480dff0f0000'      # or      rax, 0FFFh
    '4883c001'          # add     rax, 1

  # '48890544be0100'    # mov     cs:next, rax      ; Original, RIP-relative
    '48B9{next_}'       # mov     rcx, &cs:next_    ; Hand-written, absolute
    '488901'            # mov     [rcx], rax

    '488b0424'          # mov     rax, [rsp+18h+var_18]
    '4883c418'          # add     rsp, 18h
    'c3'                # retn
)

###############################################################################
# Code Carving i.e. function extraction
###############################################################################
# Why:
# To extend Code Grafting by adding function opcodes to the library already
# present here.
#
# How to use:
# 1.) Build a binary with native code to replace your functions of interest.
# 2.) Use emit_fnbytes_ascii() or emit_fnbytes_python() to get hex bytes you
#     can use in Python. For simple functions, the former is fine. For more
#     complicated functions, the latter includes useful disassembly comments.
# 3.) Add the function to g_fnbytes or g_fnbytes_allocators as appropriate
#     either after importing this module or by modifying this module.
# 4.) In the IDB for your sample, you can then import this and execute:
#       CodeGrafter().graftCodeToIdb()


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
    return _emit_fnbytes(_emit_ascii, header, footer, indent, fva, warn)


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
    return _emit_fnbytes(_emit_for_python, header, footer, indent, fva, warn)


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
    return _emit_fnbytes(_emit_for_c, header, footer, indent, fva, warn)


def _emit_for_c(va, the_bytes, size):
    disas = idc.GetDisasm(va)
    byte_buf = ''.join(['\\x%s' % (binascii.hexlify(c)) for c in the_bytes])
    return '"%s" /* %s */\n' % (byte_buf, disas)


def _emit_for_python(va, the_bytes, size):
    disas = idc.GetDisasm(va)
    return "'%s' # %s\n" % (binascii.hexlify(the_bytes), disas)


def _emit_ascii(va, the_bytes, size):
    return binascii.hexlify(the_bytes)


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
    #   1: General Register (al,ax,es,ds...)
    #   3: Base + Index
    #   4: Base + Index + Displacement
    #   5: Immediate
    #   7: Immediate Near Address
    # Notably missing because I want to note and handle these if/as they are
    # encountered:
    #   8: FPP register
    #   9: 386 control register
    #   10: 386 debug register
    #   11: 386 trace register
    optypes_position_independent = set([1, 3, 4, 5, 7])

    va = fva
    nm = idc.Name(fva)
    optypes_found = set()
    s = header.format(name=nm)
    while va != va_end:
        size = idc.get_item_size(va)
        the_bytes = idc.GetManyBytes(va, size)

        for i in range(0, 8):
            optype = idc.get_operand_type(va, i)
            if optype:
                optypes_found.add(optype)

        s += indent + emit_instr_cb(va, the_bytes, size)
        va = idc.NextHead(va)
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


###############################################################################
# Code Grafting i.e. function injection
###############################################################################
# Why:
# For statically linking stand-in functions to aid emulation under e.g. Bochs.


class CodeGraftingUnsupportedFunc(Exception):
    pass


class CodeGraftingUnsupportedArch(Exception):
    pass


class CodeGraftingDisplacementError(Exception):
    pass


class CodeGraftingAlreadyPresent(Exception):
    pass


class CodeGrafter():
    """Graft code into IDA database to allow emulation of functions that call
    certain imports and memory allocators.

    To use:
    1. Instantiate a `CodeGrafter`
    2. Call the `graftCodeToIdb()` method
    """
    def __init__(self, cpu=None, bits=None):
        self.cpu = cpu or idaapi.get_inf_structure().procname
        self.bits = bits or mykutils.get_bitness()

        self._emu_stubs = {
            ('IsDebuggerPresent',): self.get_fnbytes('retn0'),
            ('InitializeCriticalSection', 'EnterCriticalSection',
             'LeaveCriticalSection', 'DeleteCriticalSection',
             'EncodePointer', 'DecodePointer'):
                self.get_fnbytes('retn0_1arg'),
            ('FlsSetValue', '___acrt_FlsSetValue@8'):
                self.get_fnbytes('retn1_2arg'),
            ('FlsGetValue', '___acrt_FlsGetValue@4'):
                self.get_fnbytes('retn1_1arg'),
            ('setlocale', '_setlocale', '__setlocale'):
                self.get_fnbytes('setlocale'),
            ('wsetlocale', '_wsetlocale', '__wsetlocale',):
                self.get_fnbytes('wsetlocale'),
            ('GetLastError',): self.get_fnbytes('retn0'),
            ('SetLastError',): self.get_fnbytes('retn0_1arg'),
            ('CreateThread',): self.get_fnbytes('retn1_6arg'),
            ('free', '_free', '??3@YAXPAX@Z'): self.get_fnbytes('retn0'),
            ('HeapFree',): self.get_fnbytes('retn0_3arg'),
            ('strcpy', '_strcpy'): self.get_fnbytes('strcpy'),
            ('strlen',): self.get_fnbytes('strlen'),
            ('lstrlenA',): self.get_fnbytes('strlen'),
            ('memcpy', '_memcpy'): self.get_fnbytes('memcpy'),
            ('memset', '_memset'): self.get_fnbytes('memset'),
        }

    def _stubname(self, s):
        return 'stub_%s' % (s)

    def get_fnbytes(self, fname):
        return self._lookup_bytes(g_fnbytes, fname)

    def get_fnbytes_allocator(self, fname):
        return self._lookup_bytes(g_fnbytes_allocators, fname)

    def _lookup_bytes(self, table, fname):
        try:
            return table[self.cpu][self.bits][fname]
        except LookupError as e:
            if str(e)[1:-1] == fname:
                raise CodeGraftingUnsupportedFunc('Function %s not supported' %
                                                  (fname))
            else:
                raise CodeGraftingUnsupportedArch('%s-bit %s not supported' %
                                                  (self.bits, self.cpu))

    def graftCodeToIdb(self, mem=0x4000000):
        """Add segments, inject stub functions, and patch calls within IDB to
        point to the stubs.

        Args:
            mem (numbers.Integral): Size of segment to use for memory
                allocators. The more generous, the less likelihood of running
                out of memory due to successive calls to e.g. malloc and
                crashing your emulator, Bochs debug session, etc. Unless or
                until someone is brave enough to implement a stub malloc
                implementation that supports free(), this unfortunately has to
                be pretty sizeable in practice.
        """
        if self._findGraftedSegments():
            msg = ('Found grafted code segments; use '
                   'removeGraftedCodeFromIdb() first if you want to graft '
                   'anew')
            raise CodeGraftingAlreadyPresent(msg)
        self._addSegments(mem)
        return self._patchCalls()

    def removeGraftedCodeFromIdb(self):
        grafted = self._findGraftedSegments()
        if grafted:
            self._unpatchCalls(grafted)

        for seg in grafted:
            idc.del_segm(seg.start, idc.SEGMOD_KILL)

    def _findGraftedSegments(self):
        return [s for s in SegPlanner() if
                idc.get_cmt(s.start, 1) == g_seg_sig_code_grafter]

    def _addSegments(self, mem=0x4000000):
        """Create emulation stub segments.

        Includes generous memory allocation space by default.
        """
        arena_seg_size = mem
        code_seg_size = 0x1000

        use32 = 1
        fmt_ptr_width = '<I'
        if self.bits == 64:
            use32 = 2
            fmt_ptr_width = '<Q'

        def le_hex(n):  # Little-endian N-bit hex
            return binascii.hexlify(struct.pack(fmt_ptr_width, n))

        seg_plan = SegPlanner()

        # Pick locations for the code and the malloc "arena"
        #
        # Note 1: Find space for stub code segment first, making use of
        # SegPlanner's bias in planning new segments close to other segments if
        # possible. This violates the Franklin-Covey principle of fitting big
        # stones in first before smaller stones create spatial fragmentation in
        # the jar. But in a 64-bit IDB, depending on the size of the malloc
        # arena, doing this in the opposite order could increase the chance of
        # a stub function residing at a distance from its callsite that cannot
        # be represented in 32 bits.
        #
        # Note 2: SegPlanner ensures segments won't start at 0, which otherwise
        # could result in a NULL return from an allocator stub like malloc
        # erroneously signifying failure.
        code = seg_plan.addSegAnywhere(code_seg_size)
        arena = seg_plan.addSegAnywhere(arena_seg_size)

        for seg in (code, arena):
            idc.AddSeg(seg.start, seg.end, 0, use32, 0, idc.scPub)
            idc.set_cmt(seg.start, g_seg_sig_code_grafter, 1)

        # Designate location for the malloc "arena"
        va_arena = arena.start

        # Designate location for and write the malloc next-index pointer.
        #
        # Placing this before our fake heap would misalign the first allocation
        # or waste space when the allocator skips bytes to compensate for
        # alignment.
        #
        # Placing it at the end of our fake heap would risk corrupting it in
        # the event of a buffer overrun (or heap overrun).
        #
        # Assuming 64-bit to provide enough space irrespective of architecture
        va_malloc_next = code.start
        idc.patch_qword(va_malloc_next, 0)
        idc.create_qword(va_malloc_next)
        idc.set_name(va_malloc_next, self._stubname('malloc_next'), idc.SN_CHECK)
        va_next_code = code.start + 0x10

        def next_addr_align4(base, sc):
            return mykutils.align(base + (len(sc) / 2), 4)

        def add_stub_func(va, sc, nm):
            idaapi.patch_bytes(va, binascii.unhexlify(sc))
            idc.create_insn(va)
            idc.add_func(va)
            idc.set_name(va, self._stubname(nm), idc.SN_CHECK)
            cmt = ('%s implementation generated by FLARE Code Grafter' %
                   (nm))
            idc.set_cmt(va, cmt, 1)

        # Allocators are handled specially because their templates must be
        # filled with addresses for the global data they access
        for allocator_name in g_allocators_aliases:
            code = self.get_fnbytes_allocator(allocator_name).format(
                next_=le_hex(va_malloc_next),
                arena=le_hex(va_arena)
            )
            add_stub_func(va_next_code, code, allocator_name)
            va_next_code = next_addr_align4(va_next_code, code)

        # Functions not referencing data or other code are simpler:
        for names, sc in self._emu_stubs.items():
            for nm in names:
                add_stub_func(va_next_code, sc, nm)
                va_next_code = next_addr_align4(va_next_code, sc)

    def _get_imp_for_register_call(self, va_call, nm=None):
        if idc.print_insn_mnem(va_call) != 'call':
            msg = 'va_call must be the virtual address of a call instruction'
            raise ValueError(msg)

        reg = idc.print_operand(va_call, 0)
        va_mov = mykutils.find_instr(va_call, 'up', 'mov',
                                     [(0, 1, reg), (1, 2, None)])
        if not va_mov:
            return None

        if nm and (nm not in idc.print_operand(va_mov, 1)):
            return None

        va_imp = idc.get_operand_value(va_mov, 1)
        return va_imp

    def _patchCalls(self):
        def do_patch_call(va):
            retval = False
            stub_loc = idc.get_name_ea_simple(self._stubname(nm))

            # Preserve original disassembly and format new comment
            old_target = idc.print_operand(va, 0)
            orig_cmt = idc.get_cmt(va, 0) or ''
            new_cmt = '%s\n\t%s' % (g_patched_call_cmt, idc.GetDisasm(va))

            if idc.get_operand_type(va, 0) == 2:  # e.g. call ds:HeapAlloc
                retval = patch_import(va, self._stubname(nm))
                new_cmt += '\n%s %s to %s)' % (g_cmt_pointed, old_target,
                                               self._stubname(nm))
            elif idc.get_operand_type(va, 0) == 1:  # e.g. call ebx ; HeapAlloc
                va_imp = self._get_imp_for_register_call(va, nm)
                if va_imp:
                    patch_pointer_width(va_imp, stub_loc)
                    retval = True
                else:
                    logger.warn('Could not find import to patch call at %s' %
                                (phex(va)))

            else:  # Usually optype 7 otherwise
                # Won't work if displacement exceeds 32-bit operand size
                call_offset_loc = va + idc.get_item_size(va)
                if abs(call_offset_loc - stub_loc) > 0x100000000:
                    msg = ('Call site at %s too far from %s (%s)' %
                           (phex(va), self._stubname(nm), phex(stub_loc)))
                    raise CodeGraftingDisplacementError(msg)
                retval = patch_call(va, self._stubname(nm))

            if retval:
                if orig_cmt:
                    new_cmt += '\n%s' % (orig_cmt)
                idc.set_cmt(va, new_cmt, 0)
                ida_xref.add_cref(va, stub_loc, ida_xref.fl_CN)

            return retval

        for names in self._emu_stubs.keys():
            for nm in names:
                va = idc.get_name_ea_simple(nm)
                mykutils.for_each_call_to(do_patch_call, va)

        for nm, aliases in g_allocators_aliases.items():
            for alias in aliases:
                # do_patch_call closure will turn <nm> into stub_<nm>
                mykutils.for_each_call_to(do_patch_call,
                                          idc.get_name_ea_simple(alias))

    def _unpatchCalls(self, grafted_segs):
        def do_unpatch_call(va_callsite):
            size = idc.get_item_size(va_callsite)
            ida_xref.del_cref(va_callsite, fva_stub, 0)
            cmt = idc.get_cmt(va_callsite, 0)

            newcmt = cmt

            # Remove automated comments
            if newcmt.startswith(g_patched_call_cmt):
                newcmt = newcmt[newcmt.find('\n') + 1:]
                if newcmt.find('\n') == -1:
                    newcmt = ''
                else:
                    newcmt = newcmt[newcmt.find('\n') + 1:]
                if newcmt.startswith(g_cmt_pointed):
                    if newcmt.find('\n') == -1:
                        newcmt = ''
                    else:
                        newcmt = newcmt[newcmt.find('\n') + 1:]

            if newcmt != cmt:
                idc.set_cmt(va_callsite, newcmt, 0)

            if idc.get_operand_type(va_callsite, 0) == 2:
                patch_import(va_callsite, idc.BADADDR)
            elif idc.get_operand_type(va_callsite, 0) == 1:
                va_imp = self._get_imp_for_register_call(va_callsite)
                if va_imp:
                    patch_pointer_width(va_imp, idc.BADADDR)
            else:
                revert_patch(va_callsite, size)

        for fva_stub in idautils.Functions():
            for seg in grafted_segs:
                if fva_stub in seg:
                    mykutils.for_each_call_to(do_unpatch_call, fva_stub)


def patch_pointer_width(va, value):
    g_patch_pointer_width[mykutils.get_bitness()](va, value)


def patch_import(va, target):
    """Patch the import corresponding to the call at @va to point to @target.

    Args:
        va (numbers.Integral): Address of call site for imported function
        target (str): Name or address of new call destination for import entry

    Returns:
        bool: True if successful
    """
    is_call = idc.print_insn_mnem(va) == 'call'

    if is_call:
        opno = 0
    else:
        logger.warn('Not a call instruction at %s' % (phex(va)))
        return False

    if isinstance(target, basestring):
        target = idc.get_name_ea_simple(target)

    patch_pointer_width(idc.get_operand_value(va, opno), target)

    return True


def patch_call(va, new_nm):
    """Patch the call at @va to target @new_nm.

    Args:
        va (numbers.Integral): Address of the call site
        new_nm (str): Name of the new call destination

    Returns:
        bool: True if successful
    """
    is_call = idc.print_insn_mnem(va) == 'call'

    if is_call:
        opno = 0
        new_asm = 'call %s' % (new_nm)
    else:
        logger.warn('Not a call instruction at %s' % (phex(va)))
        return False

    # Already done?
    if idc.print_operand(va, opno) == new_nm:
        return True

    ok, code = idautils.Assemble(va, new_asm)

    if not ok:
        logger.warn('Failed assembling %s: %s' % (phex(va), new_asm))
        return False

    orig_opcode_len = idc.get_item_size(va)
    new_code_len = len(code)

    if orig_opcode_len < new_code_len:
        logger.warn('Not enough room or wrong opcode type to patch %s: %s' %
                    (phex(va), new_asm))
        return False

    # If we actually have too much room, then add filler
    if orig_opcode_len > new_code_len:
        delta = orig_opcode_len - new_code_len
        code += '\x90' * delta

    idaapi.patch_bytes(va, code)

    return True


def revert_patch(va, nr):
    """Unpatch the opcodes at @va, reverting them to their original value.

    Args:
        va (numbers.Integral): Address of the location of the patch to revert
        nr (numbers.Integral): Number of bytes to scan and revert

    Returns:
        bool: True if patched bytes were restored
    """
    ret = False

    orig = [ida_bytes.get_original_byte(va + i) for i in range(nr)]
    current = [idc.get_wide_byte(va + i) for i in range(nr)]

    for i in range(len(orig)):
        if orig[i] != current[i]:
            ret = True
            idaapi.patch_byte(va + i, orig[i])

    return ret
