# -*- coding: utf-8 -*-
# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""IDA utils by @mykill"""

import idc
import idaapi
import idautils
import ida_kernwin

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2019 FireEye, Inc.'
__license__ = 'Apache License 2.0'
__version__ = '1.0'

# There is much more to this library, but it needn't be code reviewed or
# publicly released until/unless needed to support future flare-ida tools.

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


def get_bitness():
    """Get the architecture bit width of this IDB."""
    inf = idaapi.get_inf_structure()
    return 64 if inf.is_64bit() else 32 if inf.is_32bit() else 16


def for_each_call_to(callback, va=None):
    """For each xref to va that is a call, pass xref va to callback.

    Falls back to highlighted identifier or current location if va is
    unspecified.
    """
    if not va:
        nm = ida_kernwin.get_highlighted_identifier()
        va = idc.LocByName(nm)
        if va >= idaapi.cvar.inf.maxEA:
            va = None

    va = va or idc.here()

    # Obtain and de-duplicate addresses of xrefs that are calls
    callsites = set([x.frm for x in idautils.XrefsTo(va)
                     if idc.GetMnem(x.frm) == 'call'])
    for va in callsites:
        callback(va)
