# -*- coding: utf-8 -*-
# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.

"""IDA segment helpers for planning segment addition"""

import idc
import bisect
import idautils
from collections import namedtuple

from mykutils import phex

__author__ = 'Michael Bailey'
__copyright__ = 'Copyright (C) 2019 FireEye, Inc.'
__license__ = 'Apache License 2.0'
__version__ = '1.0'


class Segment(namedtuple('Segment', 'start end')):
    """For reasoning over segments."""

    def __repr__(self):
        return 'Segment(start=%s, end=%s)' % (phex(self.start), phex(self.end))

    def __contains__(self, item):
        if isinstance(item, Segment):
            return self._contains_segment(item)
        return self._contains_va(item)

    def _contains_segment(self, some_seg):
        return ((self.start in some_seg) or ((self.end - 1) in some_seg) or
                (some_seg.start in self) or ((some_seg.end - 1) in self))

    def __lt__(self, va_or_seg):
        if isinstance(va_or_seg, Segment):
            return self.start < va_or_seg.start
        return self.start < va_or_seg

    def _contains_va(self, va):
        return va >= self.start and va < self.end

    def __len__(self):
        return self.end - self.start

    def __add__(self, other):
        if isinstance(other, Segment):
            self.start = min(self.start, other.start)
            self.end = max(self.end, other.end)
        else:
            self.start += other
            self.end += other


class SegPlanner():
    """For planning (but not implementing) where to add segments."""

    def __init__(self):
        self._segs = [Segment(va, idc.get_segm_end(va))
                      for va in idautils.Segments()]
        self._segs.sort()

    def __iter__(self):
        return iter(self._segs)

    def __contains__(self, va_or_seg):
        try:
            self[va_or_seg]
        except LookupError:
            return False
        return True

    def __getitem__(self, va_or_seg):
        for seg in self._segs:
            if va_or_seg in seg:
                return seg
        raise IndexError('virtual address not in any range')

    def addSeg(self, seg):
        """Add a specific segment to the planner (but not to the IDB).
        """
        if seg:
            bisect.insort(self._segs, seg)

        return seg

    def addSegAnywhere(self, size, aligned4k=True):
        """Add a segment to the planner (but not to the IDB).

        This structure is for planning purposes when adding multiple segments.
        After planning is complete, you must actually add the segments, such as
        by calling `idc.AddSeg`. Example:
            idc.AddSeg(seg.start, seg.end, 0, 1, 0, idc.scPub)

        """
        seg = self.findAvailableSegment(size, aligned4k)
        return self.addSeg(seg)

    def findAvailableSegment(self, size, aligned4k=True):
        """Find space for segments as near as possible to existing segments.

        This affinity stands to decrease the offset between code and call
        targets, allowing five-byte E8 call instructions to be patched in where
        a greater distance might result in failure e.g. for a 64-bit address
        space. In case of severe fragmentation, three strategies are employed:
            1. Attempt to insert after existing segments
            2. Attempt to insert before existing segments
            3. Attempt to insert near the bottom of memory (yuck)
        """
        va_bottom = 0x10000  # Avoid NULL page and Bochs loader segment

        # First, try to come after an existing segment
        for seg in self:
            va_start = seg.end
            if aligned4k:
                va_start = ((va_start - 1) | 0xfff) + 1

            tryseg = Segment(va_start, va_start + size)
            if tryseg not in self:
                return tryseg

        # Failing that, aim for before each existing segment
        for seg in self:
            va_start = seg.start - size
            if aligned4k:
                va_start = va_start & 0xfffffffffffff000
            tryseg = Segment(va_start, va_start + size)
            if tryseg not in self:
                return tryseg

        # Worst case, try for the bottom of memory
        tryseg = Segment(va_bottom, va_bottom + size)
        if tryseg not in self:
            return tryseg

        return None

    def __repr__(self):
        return '%r' % (self._segs)
