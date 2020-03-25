# -*- coding: utf-8 -*-
# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""Code grafting: Static linking of code into IDA Databases to aid emulation.

Code Grafting allows you to graft static implementations of imported
functions into your IDA Database (IDB) for purposes of emulation in Bochs IDB
mode or by other emulators.

Instructions for adding new code to the library of synthetic import function
implementations supported by Code Grafter:

1.) Build a binary with position-independent native code to replace your
    functions of interest.
2.) Open your binary in IDA Pro and import/use `mykutils.emit_fnbytes_python()`
    to obtain a Python-compatible hex string containing the function's opcodes.
3.) Add the resulting string to `code_grafter.g_fnbytes` (defined in
    `code_grafter.py`).
4.) In the IDB for your sample, you can then import `code_grafter` and graft
    code onto your IDB to support emulation of the function that you just added
    to the function implementation library.

      from flare import code_grafter
      cg = code_grafter.CodeGrafter()
      cg.graftCodeToIdb()

If you don't want to modify your copy of `code_grafter.py`, you may find it
possible to instead add your extracted function opcode strings to a separate
script, then import `code_grafter` and dynamically add the opcdoe strings to 
`code_grafter.g_fnbytes` before using Code Grafter on your IDB.
"""

import idc
import ida_ua
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
    '55'                        # 0x1000: push     ebp
    '8BEC'                      # 0x1001: mov      ebp, esp
    '83EC08'                    # 0x1003: sub      esp, 8
    '8B4508'                    # 0x1006: mov      eax, dword ptr [ebp + 8]
    '8945F8'                    # 0x1009: mov      dword ptr [ebp - 8], eax
    '8B4D0C'                    # 0x100c: mov      ecx, dword ptr [ebp + 0xc]
    '894DFC'                    # 0x100f: mov      dword ptr [ebp - 4], ecx
    '8B5510'                    # 0x1012: mov      edx, dword ptr [ebp + 0x10]
    '8B4510'                    # 0x1015: mov      eax, dword ptr [ebp + 0x10]
    '83E801'                    # 0x1018: sub      eax, 1
    '894510'                    # 0x101b: mov      dword ptr [ebp + 0x10], eax
    '85D2'                      # 0x101e: test     edx, edx
    '741E'                      # 0x1020: je       0x1040
    '8B4DF8'                    # 0x1022: mov      ecx, dword ptr [ebp - 8]
    '8B55FC'                    # 0x1025: mov      edx, dword ptr [ebp - 4]
    '8A02'                      # 0x1028: mov      al, byte ptr [edx]
    '8801'                      # 0x102a: mov      byte ptr [ecx], al
    '8B4DF8'                    # 0x102c: mov      ecx, dword ptr [ebp - 8]
    '83C101'                    # 0x102f: add      ecx, 1
    '894DF8'                    # 0x1032: mov      dword ptr [ebp - 8], ecx
    '8B55FC'                    # 0x1035: mov      edx, dword ptr [ebp - 4]
    '83C201'                    # 0x1038: add      edx, 1
    '8955FC'                    # 0x103b: mov      dword ptr [ebp - 4], edx
    'EBD2'                      # 0x103e: jmp      0x1012
    '8B4508'                    # 0x1040: mov      eax, dword ptr [ebp + 8]
    '8BE5'                      # 0x1043: mov      esp, ebp
    '5D'                        # 0x1045: pop      ebp
    'C3'                        # 0x1046: ret
    )
g_fnbytes[METAPC][64]['memcpy'] = (
    '4C89442418'                # 0x1000: mov       qword ptr [rsp + 0x18], r8
    '4889542410'                # 0x1005: mov       qword ptr [rsp + 0x10], rdx
    '48894C2408'                # 0x100a: mov       qword ptr [rsp + 8], rcx
    '4883EC18'                  # 0x100f: sub       rsp, 0x18
    '488B442420'                # 0x1013: mov       rax, qword ptr [rsp + 0x20]
    '4889442408'                # 0x1018: mov       qword ptr [rsp + 8], rax
    '488B442428'                # 0x101d: mov       rax, qword ptr [rsp + 0x28]
    '48890424'                  # 0x1022: mov       qword ptr [rsp], rax
    '488B4C2430'                # 0x1026: mov       rcx, qword ptr [rsp + 0x30]
    '488B442430'                # 0x102b: mov       rax, qword ptr [rsp + 0x30]
    '4883E801'                  # 0x1030: sub       rax, 1
    '4889442430'                # 0x1034: mov       qword ptr [rsp + 0x30], rax
    '4885C9'                    # 0x1039: test      rcx, rcx
    '742A'                      # 0x103c: je        0x1068
    '488B4C2408'                # 0x103e: mov       rcx, qword ptr [rsp + 8]
    '488B0424'                  # 0x1043: mov       rax, qword ptr [rsp]
    '0FB600'                    # 0x1047: movzx     eax, byte ptr [rax]
    '8801'                      # 0x104a: mov       byte ptr [rcx], al
    '488B442408'                # 0x104c: mov       rax, qword ptr [rsp + 8]
    '4883C001'                  # 0x1051: add       rax, 1
    '4889442408'                # 0x1055: mov       qword ptr [rsp + 8], rax
    '488B0424'                  # 0x105a: mov       rax, qword ptr [rsp]
    '4883C001'                  # 0x105e: add       rax, 1
    '48890424'                  # 0x1062: mov       qword ptr [rsp], rax
    'EBBE'                      # 0x1066: jmp       0x1026
    '488B442420'                # 0x1068: mov       rax, qword ptr [rsp + 0x20]
    '4883C418'                  # 0x106d: add       rsp, 0x18
    'C3'                        # 0x1071: ret
    )

g_fnbytes[METAPC][32]['memset'] = (
    '55'                        # 0x1000: push     ebp
    '8BEC'                      # 0x1001: mov      ebp, esp
    '51'                        # 0x1003: push     ecx
    '8B4508'                    # 0x1004: mov      eax, dword ptr [ebp + 8]
    '8945FC'                    # 0x1007: mov      dword ptr [ebp - 4], eax
    '8B4D10'                    # 0x100a: mov      ecx, dword ptr [ebp + 0x10]
    '8B5510'                    # 0x100d: mov      edx, dword ptr [ebp + 0x10]
    '83EA01'                    # 0x1010: sub      edx, 1
    '895510'                    # 0x1013: mov      dword ptr [ebp + 0x10], edx
    '85C9'                      # 0x1016: test     ecx, ecx
    '7413'                      # 0x1018: je       0x102d
    '8B45FC'                    # 0x101a: mov      eax, dword ptr [ebp - 4]
    '8A4D0C'                    # 0x101d: mov      cl, byte ptr [ebp + 0xc]
    '8808'                      # 0x1020: mov      byte ptr [eax], cl
    '8B55FC'                    # 0x1022: mov      edx, dword ptr [ebp - 4]
    '83C201'                    # 0x1025: add      edx, 1
    '8955FC'                    # 0x1028: mov      dword ptr [ebp - 4], edx
    'EBDD'                      # 0x102b: jmp      0x100a
    '8B4508'                    # 0x102d: mov      eax, dword ptr [ebp + 8]
    '8BE5'                      # 0x1030: mov      esp, ebp
    '5D'                        # 0x1032: pop      ebp
    'C3'                        # 0x1033: ret
    )
g_fnbytes[METAPC][64]['memset'] = (
    '4C89442418'                # 0x1000: mov       qword ptr [rsp + 0x18], r8
    '89542410'                  # 0x1005: mov       dword ptr [rsp + 0x10], edx
    '48894C2408'                # 0x1009: mov       qword ptr [rsp + 8], rcx
    '4883EC18'                  # 0x100e: sub       rsp, 0x18
    '488B442420'                # 0x1012: mov       rax, qword ptr [rsp + 0x20]
    '48890424'                  # 0x1017: mov       qword ptr [rsp], rax
    '488B4C2430'                # 0x101b: mov       rcx, qword ptr [rsp + 0x30]
    '488B442430'                # 0x1020: mov       rax, qword ptr [rsp + 0x30]
    '4883E801'                  # 0x1025: sub       rax, 1
    '4889442430'                # 0x1029: mov       qword ptr [rsp + 0x30], rax
    '4885C9'                    # 0x102e: test      rcx, rcx
    '7419'                      # 0x1031: je        0x104c
    '488B0C24'                  # 0x1033: mov       rcx, qword ptr [rsp]
    '0FB6442428'                # 0x1037: movzx     eax, byte ptr [rsp + 0x28]
    '8801'                      # 0x103c: mov       byte ptr [rcx], al
    '488B0424'                  # 0x103e: mov       rax, qword ptr [rsp]
    '4883C001'                  # 0x1042: add       rax, 1
    '48890424'                  # 0x1046: mov       qword ptr [rsp], rax
    'EBCF'                      # 0x104a: jmp       0x101b
    '488B442420'                # 0x104c: mov       rax, qword ptr [rsp + 0x20]
    '4883C418'                  # 0x1051: add       rsp, 0x18
    'C3'                        # 0x1055: ret
    )

g_fnbytes[METAPC][32]['strcpy'] = (
    '55'                        # 0x1000: push      ebp
    '8BEC'                      # 0x1001: mov       ebp, esp
    '51'                        # 0x1003: push      ecx
    '8B4508'                    # 0x1004: mov       eax, dword ptr [ebp + 8]
    '8945FC'                    # 0x1007: mov       dword ptr [ebp - 4], eax
    '8B4DFC'                    # 0x100a: mov       ecx, dword ptr [ebp - 4]
    '8B550C'                    # 0x100d: mov       edx, dword ptr [ebp + 0xc]
    '8A02'                      # 0x1010: mov       al, byte ptr [edx]
    '8801'                      # 0x1012: mov       byte ptr [ecx], al
    '8B4DFC'                    # 0x1014: mov       ecx, dword ptr [ebp - 4]
    '0FBE11'                    # 0x1017: movsx     edx, byte ptr [ecx]
    '8B45FC'                    # 0x101a: mov       eax, dword ptr [ebp - 4]
    '83C001'                    # 0x101d: add       eax, 1
    '8945FC'                    # 0x1020: mov       dword ptr [ebp - 4], eax
    '8B4D0C'                    # 0x1023: mov       ecx, dword ptr [ebp + 0xc]
    '83C101'                    # 0x1026: add       ecx, 1
    '894D0C'                    # 0x1029: mov       dword ptr [ebp + 0xc], ecx
    '85D2'                      # 0x102c: test      edx, edx
    '7402'                      # 0x102e: je        0x1032
    'EBD8'                      # 0x1030: jmp       0x100a
    '8B4508'                    # 0x1032: mov       eax, dword ptr [ebp + 8]
    '8BE5'                      # 0x1035: mov       esp, ebp
    '5D'                        # 0x1037: pop       ebp
    'C3'                        # 0x1038: ret
    )
g_fnbytes[METAPC][64]['strcpy'] = (
    '4889542410'                # 0x1000: mov       qword ptr [rsp + 0x10], rdx
    '48894C2408'                # 0x1005: mov       qword ptr [rsp + 8], rcx
    '4883EC18'                  # 0x100a: sub       rsp, 0x18
    '488B442420'                # 0x100e: mov       rax, qword ptr [rsp + 0x20]
    '48890424'                  # 0x1013: mov       qword ptr [rsp], rax
    '488B0C24'                  # 0x1017: mov       rcx, qword ptr [rsp]
    '488B442428'                # 0x101b: mov       rax, qword ptr [rsp + 0x28]
    '0FB600'                    # 0x1020: movzx     eax, byte ptr [rax]
    '8801'                      # 0x1023: mov       byte ptr [rcx], al
    '488B0424'                  # 0x1025: mov       rax, qword ptr [rsp]
    '0FBE08'                    # 0x1029: movsx     ecx, byte ptr [rax]
    '488B0424'                  # 0x102c: mov       rax, qword ptr [rsp]
    '4883C001'                  # 0x1030: add       rax, 1
    '48890424'                  # 0x1034: mov       qword ptr [rsp], rax
    '488B442428'                # 0x1038: mov       rax, qword ptr [rsp + 0x28]
    '4883C001'                  # 0x103d: add       rax, 1
    '4889442428'                # 0x1041: mov       qword ptr [rsp + 0x28], rax
    '85C9'                      # 0x1046: test      ecx, ecx
    '7402'                      # 0x1048: je        0x104c
    'EBCB'                      # 0x104a: jmp       0x1017
    '488B442420'                # 0x104c: mov       rax, qword ptr [rsp + 0x20]
    '4883C418'                  # 0x1051: add       rsp, 0x18
    'C3'                        # 0x1055: ret
    )

g_strlen_metapc_32bit = (
    '55'                        # 0x1000: push      ebp
    '8BEC'                      # 0x1001: mov       ebp, esp
    '51'                        # 0x1003: push      ecx
    'C745FC00000000'            # 0x1004: mov       dword ptr [ebp - 4], 0
    '8B4508'                    # 0x100b: mov       eax, dword ptr [ebp + 8]
    '0FBE08'                    # 0x100e: movsx     ecx, byte ptr [eax]
    '8B5508'                    # 0x1011: mov       edx, dword ptr [ebp + 8]
    '83C201'                    # 0x1014: add       edx, 1
    '895508'                    # 0x1017: mov       dword ptr [ebp + 8], edx
    '85C9'                      # 0x101a: test      ecx, ecx
    '740B'                      # 0x101c: je        0x1029
    '8B45FC'                    # 0x101e: mov       eax, dword ptr [ebp - 4]
    '83C001'                    # 0x1021: add       eax, 1
    '8945FC'                    # 0x1024: mov       dword ptr [ebp - 4], eax
    'EBE2'                      # 0x1027: jmp       0x100b
    '8B45FC'                    # 0x1029: mov       eax, dword ptr [ebp - 4]
    '8BE5'                      # 0x102c: mov       esp, ebp
    '5D'                        # 0x102e: pop       ebp
    'C3'                        # 0x102f: ret
    )
g_strlen_metapc_64bit = (
    '48894C2408'                # 0x1000: mov       qword ptr [rsp + 8], rcx
    '4883EC18'                  # 0x1005: sub       rsp, 0x18
    '48C7042400000000'          # 0x1009: mov       qword ptr [rsp], 0
    '488B442420'                # 0x1011: mov       rax, qword ptr [rsp + 0x20]
    '0FBE08'                    # 0x1016: movsx     ecx, byte ptr [rax]
    '488B442420'                # 0x1019: mov       rax, qword ptr [rsp + 0x20]
    '4883C001'                  # 0x101e: add       rax, 1
    '4889442420'                # 0x1022: mov       qword ptr [rsp + 0x20], rax
    '85C9'                      # 0x1027: test      ecx, ecx
    '740E'                      # 0x1029: je        0x1039
    '488B0424'                  # 0x102b: mov       rax, qword ptr [rsp]
    '4883C001'                  # 0x102f: add       rax, 1
    '48890424'                  # 0x1033: mov       qword ptr [rsp], rax
    'EBD8'                      # 0x1037: jmp       0x1011
    '488B0424'                  # 0x1039: mov       rax, qword ptr [rsp]
    '4883C418'                  # 0x103d: add       rsp, 0x18
    'C3'                        # 0x1041: ret
    )

# Covers lstrlenA
g_fnbytes[METAPC][32]['strlen'] = g_strlen_metapc_32bit
g_fnbytes[METAPC][64]['strlen'] = g_strlen_metapc_64bit

# return "en-US";
g_fnbytes[METAPC][32]['setlocale'] = (
    'E800000000'                # 0x1000: call      0x1005
    '58'                        # 0x1005: pop       eax
    '83C007'                    # 0x1006: add       eax, 7
    'C20800'                    # 0x1009: ret       8
    '656e2d555300'              # db 'en-US',0
    )
g_fnbytes[METAPC][64]['setlocale'] = (
    '488B0501000000'            # 0x1000: mov     rax, qword ptr [rip + 1]
    'C3'                        # 0x1007: ret
    '656e2d555300'              # db 'en-US',0
    )

g_fnbytes[METAPC][32]['wsetlocale'] = (
    'E800000000'                # 0x1000: call     0x1005
    '58'                        # 0x1005: pop      eax
    '83C007'                    # 0x1006: add      eax, 7
    'C20800'                    # 0x1009: ret      8
    '65006e002d00550053000000'  # text "UTF-16LE", 'en-US',0
    )
g_fnbytes[METAPC][64]['wsetlocale'] = (
    '488B0501000000'            # 0x1000: mov     rax, qword ptr [rip + 1]
    'C3'                        # 0x1007: ret
    '65006e002d00550053000000'  # text "UTF-16LE", 'en-US',0
    )

g_retn0_metapc_64bit = (
    '4831C0'                    # 0x1000: xor     rax, rax
    'C3'                        # 0x1003: ret
    )

g_retn1_metapc_64bit = (
    '4831C0'                    # 0x1000: xor     rax, rax
    '4883C001'                  # 0x1003: add     rax, 1
    'C3'                        # 0x1007: ret
    )

g_fnbytes[METAPC][32]['retn0'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    'C3'                        # 0x1002: ret
    )
g_fnbytes[METAPC][64]['retn0'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn0_1arg'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    'C20400'                    # 0x1002: ret     4
    )
g_fnbytes[METAPC][64]['retn0_1arg'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn0_3arg'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    'C20C00'                    # 0x1002: ret     0xc
    )
g_fnbytes[METAPC][64]['retn0_3arg'] = g_retn0_metapc_64bit

g_fnbytes[METAPC][32]['retn1'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    '40'                        # 0x1002: inc     eax
    'C3'                        # 0x1003: ret
    )
g_fnbytes[METAPC][64]['retn1'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_1arg'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    '40'                        # 0x1002: inc     eax
    'C20400'                    # 0x1003: ret     4
    )
g_fnbytes[METAPC][64]['retn1_1arg'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_2arg'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    '40'                        # 0x1002: inc     eax
    'C20800'                    # 0x1003: ret     8
    )
g_fnbytes[METAPC][64]['retn1_2arg'] = g_retn1_metapc_64bit

g_fnbytes[METAPC][32]['retn1_6arg'] = (
    '31C0'                      # 0x1000: xor     eax, eax
    '40'                        # 0x1002: inc     eax
    'C21800'                    # 0x1003: ret     0x18
    )
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
        mykutils.makename_safe(va_malloc_next, self._stubname('malloc_next'))
        va_next_code = code.start + 0x10

        def next_addr_align4(base, sc):
            return mykutils.align(base + (len(sc) / 2), 4)

        def add_stub_func(va, sc, nm):
            idaapi.patch_bytes(va, binascii.unhexlify(sc))
            idc.create_insn(va)
            idc.add_func(va)
            mykutils.makename_safe(va, self._stubname(nm))
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

            if idc.get_operand_type(va, 0) == ida_ua.o_mem:
                retval = patch_import(va, self._stubname(nm))
                new_cmt += '\n%s %s to %s)' % (g_cmt_pointed, old_target,
                                               self._stubname(nm))
            elif idc.get_operand_type(va, 0) == ida_ua.o_reg:
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

            if idc.get_operand_type(va_callsite, 0) == ida_ua.o_mem:
                patch_import(va_callsite, idc.BADADDR)
            elif idc.get_operand_type(va_callsite, 0) == ida_ua.o_reg:
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
