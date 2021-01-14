############################################
# Copyright (C) 2019 FireEye, Inc.
#
# Author: Moritz Raabe
#
# ironstrings is an IDAPython script that uses flare-emu (which combines Unicorn and
# IDA Pro) to recover stackstrings from malware using code emulation.
#
# Dependencies:
# https://github.com/fireeye/flare-emu
# https://github.com/unicorn-engine/unicorn
############################################

from __future__ import print_function

import time
import logging
from collections import namedtuple

import idc
import idaapi
import idautils
import unicorn

import strings
try:
    import flare_emu
except ImportError as e:
    print("Could not import flare_emu: {}\nExiting.".format(e.message))
    raise


#
# USER OPTIONS
#

# only analyze the currently selected function; otherwise analyze all functions
ANALYZE_SINGLE_FUNC = False

# jump to currently analyzed function
JUMP_TO_FUNC = False

# print listing of unique stackstrings after running
PRINT_PLAIN_SUMMARY = True

# add comments for recovered stackstrings
COMMENT_STACKSTRINGS = True

# use a repeatable comment on the global memory address
COMMENT_STACKSTRING_GLOBAL_REPEATABLE = False

# prefix used for stackstring comment
COMMENT_STACKSTRING_PREFIX = "stackstring: '"

# suffix used for stackstring comment
COMMENT_STACKSTRING_SUFFIX = "'"

#
# STACKSTRINGS RECOVERY OPTIONS
#

# maximum number of code paths to find through each function
MAX_CODE_PATHS = 10

# minimum number of memory writes in a basic block to trigger stackstring recovery
MIN_MEM_WRITE_COUNT = 5

# maximum number an instruction is repeated
MAX_INSTR_REP = 0x100

# maximum size of current stack frame
# IMPROVEMENT fine tune this value
MAX_STACK_SIZE = 0x10000


StackString = namedtuple("StackString",
                         [
                             # function address from which the stackstring was extracted
                             "fva",
                             # program counter at which the stackstring existed
                             "pc",
                             # string contents
                             "s",
                             # for local stackstring: offset from the function frame at which the stackstring
                             # existed, for globalstring: offset in global memory
                             "offset",
                             # address where first character of stackstring was written
                             "written_at",
                         ])


def main():
    eh = flare_emu.EmuHelper()

    # dictionary that stores data used across emulation runs, function emulation specific data is set below
    userData = {
        # found stackstrings in stack memory
        "stackstrings": [],
        # found stackstrings in global memory (globalstrings)
        "globalstrings": []
    }

    cnt_functions = 0
    cnt_analyzed = 0
    cnt_found_ss = 0
    cnt_commented_ss = 0
    errors = []

    start = time.time()
    print("Started ironstrings stackstring deobfuscation")
    print_header()

    if ANALYZE_SINGLE_FUNC:
        fvas = [idc.get_func_attr(idc.here(), idc.FUNCATTR_START)]
    else:
        fvas = idautils.Functions()

    for fva in fvas:
        logging.debug("running on 0x%X", fva)
        if JUMP_TO_FUNC:
            idc.jumpto(fva)

        if fva == idaapi.BADADDR:
            logging.debug("skipping invalid function address")
            continue
        if idc.get_func_flags(fva) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            logging.debug("skipping library or thunk function 0x%X", fva)
            continue

        # function start address
        userData["funcStart"] = fva

        # list of addresses of last instruction for all basic blocks in function
        userData["bb_ends"] = get_bb_ends(fva)

        # memory writes in current function
        userData["mem_writes"] = {}

        # start and end addresses of all memory writes in function
        userData["writelog"] = set()

        # memory write count in current basic block
        userData["mem_write_count"] = 0

        # cache previous address to count instructions that are executed multiple times, e.g. rep prefixed
        userData["prevAddress"] = 0

        # number same instruction has been executed in a row
        userData["repCount"] = 0

        cnt_functions += 1
        try:
            # emulate various paths through function via flare-emu, use hooks to reconstruct strings
            eh.iterateAllPaths(fva, noop, hookData=userData, callHook=call_hook, instructionHook=instr_hook,
                               memAccessHook=hook_mem_write, hookApis=False, maxPaths=MAX_CODE_PATHS)
        except unicorn.UcError as e:
            errors.append("Error analyzing function 0x{:X}: {}".format(fva, str(e)))
        else:
            cnt_analyzed += 1

            # print stackstrings found in this function
            f_ss = list(filter(lambda s: s.fva == fva, userData["stackstrings"]))
            cnt_found_ss += len(f_ss)
            for ss in sorted(f_ss, key=lambda s: s.written_at or 0):
                print_string(ss.fva, ss.written_at, ss.offset, ss.s)
                # IMPROVEMENT adjust stack frame member size in IDA view

            # print globalstrings found in this function
            f_gs = list(filter(lambda g: g.fva == fva, userData["globalstrings"]))
            cnt_found_ss += len(f_gs)
            for gs in sorted(f_gs, key=lambda g: g.written_at or 0):
                print_string(gs.fva, gs.written_at, gs.offset, gs.s)

            if COMMENT_STACKSTRINGS:
                for ss in f_ss:
                    if not ss.written_at:
                        errors.append("Can't get location where '{}' was written in 0x{:X}.".format(ss.s, ss.fva))
                        continue
                    ss_cmt = format_comment(ss.s)
                    if append_comment(ss.written_at, ss_cmt):
                        cnt_commented_ss += 1
                    else:
                        errors.append("Failed to set comment at 0x{:X}: {}".format(ss.written_at, ss_cmt))

                for gs in f_gs:
                    if COMMENT_STACKSTRING_GLOBAL_REPEATABLE:
                        repeatable = True
                        cmt_va = gs.offset
                    else:
                        repeatable = False
                        cmt_va = gs.written_at

                    if not cmt_va:
                        errors.append("Can't get location where '{}' was written in 0x{:X}.".format(gs.s, gs.fva))
                        continue
                    gs_cmt = format_comment(gs.s)
                    if append_comment(cmt_va, gs_cmt, repeatable):
                        cnt_commented_ss += 1
                    else:
                        errors.append("Failed to set comment at 0x{:X}: {}".format(cmt_va, gs_cmt))

        # update IDA view
        idc.refresh_idaview_anyway()

        # clean up memory after each function
        eh.resetEmulatorHeapAndStack()

    print_summary(cnt_functions, cnt_analyzed, cnt_found_ss, cnt_commented_ss, errors)

    if PRINT_PLAIN_SUMMARY:
        print_plain_summary(userData["stackstrings"] + userData["globalstrings"])

    print("\nFinished ironstrings stackstring deobfuscation after {:.2f} seconds".format(time.time() - start))


def instr_hook(uc, address, size, userData):
    """
    Hook that runs before every instruction. Performs emulation sanity checks.
    Extract stackstrings at end of a basic block (bb) if bb contains enough memory writes.
    No success with UC_HOOK_BLOCK as bbs may differ between IDA and Unicorn
    :param uc: Unicorn object
    :param address: current instruction address
    :param size: current instruction size
    :param userData: user-provided data
    :return: None
    """
    update_init_sp(address, userData)

    # IMPROVEMENT generalize to count maxhits for all instructions
    if address == userData["prevAddress"]:
        userData["repCount"] += 1
    if userData["repCount"] > MAX_INSTR_REP:
        logging.debug("address hit more than %d times, skipping", MAX_INSTR_REP)
        userData["repCount"] = 0
        eh = userData["EmuHelper"]
        eh.skipInstruction(userData)
    userData["prevAddress"] = address

    # trigger stackstring extraction based on number of memory writes in current bb
    if address in userData["bb_ends"]:
        if userData["mem_write_count"] >= MIN_MEM_WRITE_COUNT:
            logging.debug("end of basic block with %d memory writes", userData["mem_write_count"])
            update_stackstrings(address, userData)
            update_globalstrings(address, userData)
        # reset counter at end of basic block
        userData["mem_write_count"] = 0


def call_hook(address, argv, funcName, userData):
    """
    Hook all function calls. Extract stackstrings.
    :param address: address of call
    :param argv: call arguments
    :param funcName: name of called function
    :param userData: user-provided data
    :return: None
    """
    # IMPROVEMENT record funcName
    update_stackstrings(address, userData)
    update_globalstrings(address, userData)
    # reset memory write counter, all strings up to call have been captured
    userData["mem_write_count"] = 0


def hook_mem_write(uc, access, address, size, value, userData):
    """
    Hook all memory read and write events. Count memory writes and record written address locations.
    :param uc: Unicorn object
    :param access: memory access type
    :param address: memory address
    :param size: memory address size
    :param value: memory value
    :param userData: user-provided data
    :return: None
    """
    eh = userData["EmuHelper"]
    pc = eh.getRegVal("pc")

    # only record and count memory writes, create write log
    if access == unicorn.UC_MEM_WRITE:
        # IMPROVEMENT store multiple locations where address was written
        userData["mem_writes"][address] = pc
        userData["mem_write_count"] += 1
        userData["writelog"].add((address, address + size))


def noop(*args):
    """
    No operation callback
    :param args:
    :return: None
    """


def get_bb_ends(address):
    """
    Get end addresses of all bbs in function containing address.
    :param address: address in function
    :return: list of bb end addresses
    """
    function = idaapi.get_func(address)
    flowchart = idaapi.FlowChart(function)
    return [idc.prev_head(bb.end_ea) for bb in flowchart]


def update_init_sp(address, userData):
    """
    Hack to get stack pointer at beginning of emulation.
    :param address: current instruction address
    :param userData: user-provided data
    :return: None
    """
    eh = userData["EmuHelper"]
    if address == userData["funcStart"]:
        userData["init_sp"] = eh.getRegVal("sp")


def update_stackstrings(address, userData):
    """
    Extract stackstrings and update userData value.
    :param address: current instruction address
    :param userData: user-provided data
    :return: None
    """
    eh = userData["EmuHelper"]
    stack_top = eh.getRegVal("sp")
    stack_start, stack_end = eh.getEmuMemRegion(eh.stack)
    if stack_top < stack_start:
        stack_top = stack_start

    if "init_sp" not in userData:
        logging.debug("could not get initial SP, using base of stack: 0x%X", stack_start)
        userData["init_sp"] = stack_start
    stack_bottom = userData["init_sp"]  # SP at start of function, most of the times equal to BP
    stackstrings = userData["stackstrings"]
    mem_writes = userData["mem_writes"]

    # Extract only the bytes on the stack between stack pointer at function entry and current stack pointer
    current_stack_size = stack_bottom - stack_top
    if current_stack_size < 0:
        logging.debug("can't read negative stack size: %d", current_stack_size)
        # IMPROVEMENT return false to indicate failure
        return
    if stack_top + current_stack_size > stack_end:
        logging.debug("can't read past stack end")
        return
    if current_stack_size > MAX_STACK_SIZE:
        logging.debug("stack size too big: 0x%X", current_stack_size)
        return

    stack_buf = eh.getEmuBytes(stack_top, current_stack_size)
    logging.debug("extracting stackstrings at checkpoint: 0x%X, stacksize: 0x%X", address, current_stack_size)
    for s in extract_all_strings(stack_buf):
        logging.debug("found stackstring '%s'", s.s)
        frame_offset = current_stack_size - s.offset - eh.size_pointer
        offset, written_at = get_offset_written_at(stack_top + s.offset, mem_writes)
        ss = StackString(userData["funcStart"], address, s.s[offset:], frame_offset, written_at)
        if does_contain(stackstrings, ss) or does_contain_substr(stackstrings, ss):
            # already recovered
            continue
        if not extend_existing(ss, stackstrings):
            stackstrings.append(ss)


def update_globalstrings(address, userData):
    """
    Extract stackstrings in global memory and update userData value.
    :param address: current instruction address
    :param userData: user-provided data
    :return: None
    """
    globalstrings = userData["globalstrings"]
    mem_writes = userData["mem_writes"]
    # consolidate memory write ranges
    userData["writelog"] = set(consolidate(userData["writelog"]))

    eh = userData["EmuHelper"]
    stack_start, stack_end = eh.getEmuMemRegion(eh.stack)

    # ignore stack memory
    # IMPROVEMENT use this mechanism for all stackstrings
    userData["writelog"] = set(filter(lambda m: m[0] < stack_start or m[0] > stack_end, userData["writelog"]))

    logging.debug("extracting global stackstrings at checkpoint: 0x%X", address)
    for mem_start, mem_end in userData["writelog"]:
        bytez = eh.getEmuBytes(mem_start, mem_end - mem_start)
        for s in extract_all_strings(bytez):
            # ignore artifacts in null page
            if mem_start == 0:
                continue

            logging.debug("found globalstring '%s' at 0x%X", s.s, mem_start + s.offset)
            _, written_at = get_offset_written_at(mem_start + s.offset, mem_writes)
            gs = StackString(userData["funcStart"], address, s.s, mem_start + s.offset, written_at)
            if does_contain(globalstrings, gs) or does_contain_substr(globalstrings, gs):
                # already recovered
                continue
            if not extend_existing(gs, globalstrings):
                globalstrings.append(gs)


def extract_all_strings(stack_buf):
    """
    Extract ASCII and UTF-16 strings from buffer.
    :param stack_buf: memory buffer
    :return: Extracted String namedtuples
    """
    for s in strings.extract_ascii_strings(stack_buf):
        yield s
    for s in strings.extract_unicode_strings(stack_buf):
        yield s


def get_offset_written_at(ss_va, mem_writes):
    """
    Get instruction address where string was initially written.
    Removes false positives, e.g. when addresses got pushed that contain a part in ASCII range
    :param ss_va: identified string offset
    :param mem_writes: record of all memory writes
    :return: tuple: string offset, address where string was written
    """
    offset = 0
    written_at = None
    if ss_va in mem_writes:
        logging.debug("string in mem_writes at 0x%X", mem_writes[ss_va])
        written_at = mem_writes[ss_va]
    # one off ASCII
    elif (ss_va + 1) in mem_writes:
        logging.debug("string+1 in mem_writes at 0x%X", mem_writes[ss_va + 1])
        offset = 1
        written_at = mem_writes[ss_va + 1]
    # one off UTF-16LE
    elif (ss_va + 2) in mem_writes:
        logging.debug("string+2 in mem_writes at 0x%X", mem_writes[ss_va + 2])
        offset = 1  # still just one character off
        written_at = mem_writes[ss_va + 2]
    return offset, written_at


def consolidate(intervals):
    """
    Consolidate interval ranges via https://codereview.stackexchange.com/a/69249.
    :param intervals: set of tuples with start and end address
    :return: list of consolidated intervals
    """
    sorted_by_lower_bound = sorted(intervals, key=lambda tup: tup[0])
    merged = []
    for higher in sorted_by_lower_bound:
        if not merged:
            merged.append(higher)
        else:
            lower = merged[-1]
            # test for intersection between lower and higher:
            # we know via sorting that lower[0] <= higher[0]
            if higher[0] <= lower[1]:
                upper_bound = max(lower[1], higher[1])
                merged[-1] = (lower[0], upper_bound)  # replace by merged interval
            else:
                merged.append(higher)
    return merged


def does_contain(stackstrings, ss):
    """
    Check existence of stackstring in list.
    :param stackstrings: list of all recovered stackstrings
    :param ss: new stackstring candidate
    :return: True if candidate already in stackstring list, False otherwise
    """
    hashable_ss = (ss.fva, ss.s, ss.written_at)
    for s in stackstrings:
        hashable = (s.fva, s.s, s.written_at)
        if hashable == hashable_ss:
            return True
    return False


def does_contain_substr(stackstrings, new_ss):
    """
    Check if new string is a substring of an existing stackstring.
    :param stackstrings: list of all recovered stackstrings
    :param new_ss: new stackstring candidate
    :return: True if candidate substring of an existing stackstring, False otherwise
    """
    # IMPROVEMENT incorporate written_at in check
    for ss in filter(lambda es: es.fva == new_ss.fva, stackstrings):
        if new_ss.s in ss.s:
            return True
    return False


def extend_existing(new_string, existing_strings):
    """
    Update an existing string if a new string extends it.
    :param new_string: new recovered string
    :param existing_strings: list of already recovered strings
    :return: True if extended existing string, False otherwise
    """
    for i, existing in enumerate(existing_strings):
        if existing.s in new_string.s:
            logging.debug("updating string %s to %s", existing.s, new_string.s)
            existing_strings[i] = new_string
            return True
    return False


#
# print and comment functions
#
def print_header():
    """
    Print formatted header
    :return: None
    """
    print("{:16}   {:16}   {:16}   {:16}".format("Function", "Written at", "Offset", "String"))
    print("{s:-<16}   {s:-<16}   {s:-<16}   {s:-<16}".format(s=""))


def print_string(fva, written_at, offset, s):
    """
    Print formatted stackstring
    :param fva: function address containing stackstring
    :param written_at: instruction address where stackstring was written
    :param offset: memory offset (stack relative or global) where string was written
    :param s: recovered stackstring
    :return: None
    """
    if written_at:
        # IMPROVEMENT indicate if stack offset
        print("0x{:<16X} 0x{:<16X} 0x{:<16X} {:<}".format(fva, written_at, offset, s))
    else:
        print("0x{:<16X}   {:16} 0x{:<16X} {:<}".format(fva, "", offset, s))


def print_summary(cnt_functions, cnt_analyzed, cnt_found, cnt_commented, errors):
    """
    Print analysis summary.
    :param cnt_functions: number of identified functions
    :param cnt_analyzed: number of successfully analyzed functions
    :param cnt_found: number of recovered stackstrings
    :param cnt_commented: number of commented stackstrings
    :param errors: list of encountered error message strings
    :return: None
    """
    print("\nironstrings summary\n{:-<24}".format(""))
    print("Ran successfully on {:d}/{:d} functions".format(cnt_analyzed, cnt_functions))
    print("Found {:d} stackstrings".format(cnt_found))
    print("Commented {:d} stackstrings".format(cnt_commented))

    if errors:
        print("Encountered {:d} errors".format(len(errors)))
        for err in errors:
            print(" - {}".format(err))


def print_plain_summary(stackstrings):
    unique = get_unique_strings(stackstrings)
    print("\nRecovered {:d} unique stackstrings\n{:-<24}".format(len(unique), ""))
    for s in unique:
        print("{}".format(s))


def get_unique_strings(stackstrings):
    """
    Get unique recovered stackstrings.
    :param stackstrings: list of all stackstrings
    :return: list of unique stackstrings
    """
    unique = set()
    for ss in stackstrings:
        unique.add(ss.s)
    return unique


def format_comment(comment):
    """
    Wrap comment with prefix and suffix.
    :param comment: comment string
    :return: formatted comment string
    """
    return "{prefix}{cmt}{suffix}".format(prefix=COMMENT_STACKSTRING_PREFIX, cmt=comment,
                                          suffix=COMMENT_STACKSTRING_SUFFIX)


def append_comment(va, new_cmt, repeatable=False):
    """
    Append a comment to an address in IDA Pro.
    :param va: comment address
    :param new_cmt: comment string
    :param repeatable: if True, append as repeatable comment
    :return: True if success
    """
    cmt = idc.get_cmt(va, repeatable)
    if not cmt:
        # no existing comment
        cmt = new_cmt
    else:
        if new_cmt in cmt:
            # comment already exists
            return True
        cmt = cmt + "\n" + new_cmt
    return idc.set_cmt(va, cmt, repeatable)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
