import json
import logging
import binascii
from collections import namedtuple

from idc import *
from idaapi import *

# TODO: make this into an enum
FUNCTION_MODE_MIN = 0
NON_AUTO_FUNCTIONS = FUNCTION_MODE_MIN
LIBRARY_FUNCTIONS = 1
PUBLIC_FUNCTIONS = 2
ENTRY_POINT_FUNCTIONS = 3
ALL_FUNCTIONS = 4
USER_SELECT_FUNCTION = 5
FUNCTION_MODE_MAX = USER_SELECT_FUNCTION


def get_ida_logging_handler():
    """
    IDA logger should always be the first one (since it inits the env)
    """
    return logging.getLogger().handlers[0]


logging.basicConfig(level=logging.DEBUG)
get_ida_logging_handler().setLevel(logging.INFO)
g_logger = logging.getLogger("idb2pat")


class Config(object):
    def __init__(self, min_func_length=6, pointer_size=4, mode=ALL_FUNCTIONS, pat_append=False, logfile="", loglevel="DEBUG", logenabled=False):
        super(Config, self).__init__()
        self.min_func_length = min_func_length
        # TODO: get pointer_size from IDA
        self.pointer_size = pointer_size
        if __EA64__:
            self.pointer_size = 8
        self.mode = mode
        self.pat_append = pat_append
        self.logfile = logfile
        self.loglevel = getattr(logging, loglevel)
        self.logenabled = logenabled

    def update(self, vals):
        """
        Set these fields given a dict with a similar schema as this,
         possibly loaded from a JSON string.
        type vals: dict(string, object)
        """
        self.min_func_length = vals.get("min_func_length", self.min_func_length)
        self.pointer_size = vals.get("pointer_size", self.pointer_size)
        # TODO: make this a string, not magic number
        self.mode = vals.get("mode", self.mode)
        self.pat_append = vals.get("pat_append", self.pat_append)
        self.logfile = vals.get("logfile", self.logfile)
        self.logenabled = vals.get("logenabled", self.logenabled)

        if "loglevel" in vals:
            if hasattr(logging, vals["loglevel"]):
                self.loglevel = getattr(logging, vals["loglevel"])


# generated from IDB2SIG plugin updated by TQN
CRC16_TABLE = [
  0x0, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
  0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x108, 0x3393, 0x221a,
  0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
  0xf9ff, 0xe876, 0x2102, 0x308b, 0x210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
  0x1291, 0x318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
  0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x420, 0x15a9,
  0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
  0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
  0x2522, 0x34ab, 0x630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
  0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
  0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x840, 0x19c9, 0x2b52, 0x3adb,
  0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
  0xf1bf, 0xe036, 0x18c1, 0x948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
  0xa50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
  0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0xb58, 0x7fe7, 0x6e6e,
  0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0xc60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
  0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
  0x1ce1, 0xd68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
  0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0xe70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
  0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0xf78]


# ported from IDB2SIG plugin updated by TQN
def crc16(data, crc):
    for byte in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ ord(byte)) & 0xFF]
    crc = (~crc) & 0xFFFF
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xffff


def get_functions():
   for i in xrange(get_func_qty()):
        yield getn_func(i)


# TODO: idaapi.get_func(ea)
_g_function_cache = None
def get_func_at_ea(ea):
    """
    type ea: idc.ea_t
    """
    global _g_function_cache
    if _g_function_cache is None:
        _g_function_cache = {}
        for f in get_functions():
            _g_function_cache[f.startEA] = f

    return _g_function_cache.get(f.startEA, None)


def find_ref_loc(config, ea, ref):
    """
    type config: Config
    type ea: idc.ea_t
    type ref: idc.ea_t
    """
    logger = logging.getLogger("idb2pat:find_ref_loc")
    if ea == BADADDR:
        logger.debug("Bad parameter: ea")
        return BADADDR
    if ref == BADADDR:
        logger.debug("Bad parameter: ref")
        return BADADDR


    # TODO: handle self-relative references
    # https://github.com/nihilus/idb2pat/blob/master/idb2pat.cpp#L156

    if isCode(getFlags(ea)):
        for i in xrange(ea, get_item_end(ea) - config.pointer_size):
            if get_long(i) == ref:
                return i

    return BADADDR


def to_bytestring(seq):
    """
    convert sequence of chr()-able items to a str of
     their chr() values.
    in reality, this converts a list of uint8s to a
     bytestring.
    """
    return "".join(map(chr, seq))


class FuncTooShortException(Exception):
    pass


# ported from IDB2SIG plugin updated by TQN
def make_func_sig(config, func):
    """
    type config: Config
    type func: idc.func_t
    """
    logger = logging.getLogger("idb2pat:make_func_sig")

    if func.endEA - func.startEA < config.min_func_length:
        logger.debug("Function is too short")
        raise FuncTooShortException()

    ea = func.startEA
    publics = []  # type: idc.ea_t
    refs = {}  # type: dict(idc.ea_t, idc.ea_t)
    variable_bytes = set([])  # type: set of idc.ea_t

    while ea != BADADDR and ea < func.endEA:
        logger.debug("ea: %s", hex(ea))

        name = get_name(0, ea)
        if name is not None and name != "":
            logger.debug("has a name")
            publics.append(ea)

        ref = get_first_dref_from(ea)
        if ref != BADADDR:
            # data ref
            logger.debug("has data ref")
            ref_loc = find_ref_loc(config, ea, ref)
            if ref_loc != BADADDR:
                logger.debug("  ref loc: %s", hex(ref_loc))
                for i in xrange(config.pointer_size):
                    logger.debug("    variable %s", hex(ref_loc + i))
                    variable_bytes.add(ref_loc + i)
                refs[ref_loc] = ref

            # not sure why we only care about two...
            # only two possible operands?
            ref = get_next_dref_from(ea, ref)
            if ref != BADADDR:
                logger.debug("has data ref2")
                ref_loc = find_ref_loc(config, ea, ref)
                if ref_loc != BADADDR:
                    logger.debug("  ref loc: %s", hex(ref_loc))
                    for i in xrange(config.pointer_size):
                        logger.debug("    variable %s", hex(ref_loc + i))
                        variable_bytes.add(ref_loc + i)
                    refs[ref_loc] = ref
        else:
            # code ref
            ref = get_first_fcref_from(ea)
            if ref != BADADDR:
                logger.debug("has code ref")
                if ref < func.startEA or ref >= func.endEA:
                    # code ref is outside function
                    ref_loc = find_ref_loc(config, ea, ref)
                    if BADADDR != ref_loc:
                        logger.debug("  ref loc: %s", hex(ref_loc))
                        for i in xrange(config.pointer_size):
                            logger.debug("    variable %s", hex(ref_loc + i))
                            variable_bytes.add(ref_loc + i)
                        refs[ref_loc] = ref

        ea = next_not_tail(ea)

    sig = ""
    # first 32 bytes, or til end of function
    for ea in xrange(func.startEA, min(func.startEA + 32, func.endEA)):
        if ea in variable_bytes:
            sig += ".."
        else:
            sig += "%02X" % (get_byte(ea))

    sig += ".." * (32 - (len(sig) / 2))

    crc_data = [0 for i in xrange(256)]
    # for 255 bytes starting at index 32, or til end of function, or variable byte
    for i in xrange(32, min(func.endEA - func.startEA, 255) + 32):
        if i in variable_bytes:
            break
        crc_data[i - 32] = get_byte(func.startEA + i)

    # TODO: is this required everywhere? ie. with variable bytes?
    alen = i - 32 + 1  # plus 1 to offset the for-loop break

    crc = crc16(to_bytestring(crc_data[:alen]), crc=0xFFFF)
    sig += " %02X" % (alen)
    sig += " %04X" % (crc)
    # TODO: does this need to change for 64bit?
    sig += " %04X" % (func.endEA - func.startEA)

    # this will be either " :%04d %s" or " :%08d %s"
    public_format = " :%%0%dX %%s" % (config.pointer_size)
    for public in publics:
        name = get_name(0, public)
        if name is None or name == "":
            continue

        sig += public_format % (public - func.startEA, name)

    for ref_loc, ref in refs.iteritems():
        # TODO: what is the first arg?
        name = get_true_name(0, ref)
        if name is None or name == "":
            continue

        if ref_loc >= func.startEA:
            # this will be either " ^%04d %s" or " ^%08d %s"
            addr = ref_loc - func.startEA
            ref_format = " ^%%0%dX %%s" % (config.pointer_size)
        else:
            # this will be either " ^-%04d %s" or " ^-%08d %s"
            addrs = func.startEA - ref_loc
            ref_format = " ^-%%0%dX %%s" % (config.pointer_size)
        sig += ref_format % (addr, name)

    logger.debug("sig: %s", sig)
    return sig


def make_func_sigs(config):
    logger = logging.getLogger("idb2pat:make_func_sigs")
    sigs = []
    if config.mode == USER_SELECT_FUNCTION:
        f = choose_func("Choose Function:", BADADDR)
        if f is None:
            logger.error("No function selected")
            return []
        jumpto(f.startEA)
        if not has_any_name(getFlags(f.startEA)):
            logger.error("Function doesn't have a name")
            return []

        try:
            sigs.append(make_func_sig(config, f))
        except Exception as e:
            logger.exception(e)
            # TODO: GetFunctionName?
            logger.error("Failed to create signature for function at %s (%s)",
                hex(f.startEA), get_name(0, f.startEA) or "")

    elif config.mode == NON_AUTO_FUNCTIONS:
        for f in get_functions():
            if has_name(getFlags(f.startEA)) and func.flags & FUNC_LIB == 0:
                try:
                    sigs.append(make_func_sig(config, f))
                except FuncTooShortException:
                    pass
                except Exception as e:
                    logger.exception(e)
                    logger.error("Failed to create signature for function at %s (%s)",
                        hex(f.startEA), get_name(0, f.startEA) or "")

    elif config.mode == LIBRARY_FUNCTIONS:
        for f in get_functions():
            if has_name(getFlags(f.startEA)) and func.flags & FUNC_LIB != 0:
                try:
                    sigs.append(make_func_sig(config, f))
                except FuncTooShortException:
                    pass
                except Exception as e:
                    logger.exception(e)
                    logger.error("Failed to create signature for function at %s (%s)",
                        hex(f.startEA), get_name(0, f.startEA) or "")

    elif config.mode == PUBLIC_FUNCTIONS:
        for f in get_functions():
            if is_public_name(f.startEA):
                try:
                    sigs.append(make_func_sig(config, f))
                except FuncTooShortException:
                    pass
                except Exception as e:
                    logger.exception(e)
                    logger.error("Failed to create signature for function at %s (%s)",
                        hex(f.startEA), get_name(0, f.startEA) or "")

    elif config.mode == ENTRY_POINT_FUNCTIONS:
        for i in xrange(get_func_qty()):
            f = get_func(get_entry(get_entry_ordinal(i)))
            if f is not None:
                try:
                    sigs.append(make_func_sig(config, f))
                except FuncTooShortException:
                    pass
                except Exception as e:
                    logger.exception(e)
                    logger.error("Failed to create signature for function at %s (%s)",
                        hex(f.startEA), get_name(0, f.startEA) or "")

    elif config.mode == ALL_FUNCTIONS:
        n = get_func_qty()
        for i, f in enumerate(get_functions()):
            try:
                logger.info("[ %d / %d ] %s %s", i + 1, n, get_name(0, f.startEA), hex(f.startEA))
                sigs.append(make_func_sig(config, f))
            except FuncTooShortException:
                pass
            except Exception as e:
                logger.exception(e)
                logger.error("Failed to create signature for function at %s (%s)",
                    hex(f.startEA), get_name(0, f.startEA) or "")

    return sigs


def get_pat_file():
    logger = logging.getLogger("idb2pat:get_pat_file")
    name, extension = os.path.splitext(get_input_file_path())
    name = name + ".pat"

    filename = askfile_c(1, name, "Enter the name of the pattern file")
    if filename is None:
        logger.debug("User did not choose a pattern file")
        return None

    return filename


def update_config(config):
    logger = logging.getLogger("idb2pat:update_config")
    name, extension = os.path.splitext(get_input_file_path())
    name = name + ".conf"

    if not os.path.exists(name):
        logger.debug("No configuration file provided, using defaults")
        return

    with open(name, "rb") as f:
        t = f.read()

    try:
        vals = json.loads(t)
    except Exception as e:
        logger.exception(e)
        logger.warning("Configuration file invalid")
        return

    config.update(vals)
    return


def main():
    c = Config()
    update_config(c)

    if c.logenabled:
        h = logging.FileHandler(c.logfile)
        h.setLevel(c.loglevel)
        logging.getLogger().addHandler(h)

    filename = get_pat_file()
    if filename is None:
        g_logger.debug("No file selected")
        return

    sigs = make_func_sigs(c)

    if c.pat_append:
        with open(filename, "ab") as f:
            for sig in sigs:
                f.write(sig)
                f.write("\r\n")
            f.write("---")
            f.write("\r\n")
    else:
        with open(filename, "wb") as f:
            for sig in sigs:
                f.write(sig)
                f.write("\r\n")
            f.write("---")
            f.write("\r\n")


if __name__ == "__main__":
    main()
