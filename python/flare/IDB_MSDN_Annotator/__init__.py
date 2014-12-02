"""
IDAPython script to annotate IDB files with information extracted from the
MSDN documentation including functions, arguments and constants.

Authors: Moritz Raabe, William Ballenthin
Copyright 2014 Mandiant, A FireEye Company

Mandiant licenses this file to you under the Apache License, Version
2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.
"""

import os.path
import sys
from string import rsplit
from textwrap import fill
from time import strftime
import logging
import idc
import idautils
import idaapi
import xml_parser

from PySide import QtGui

CREATE_BACKUP = True # indicate if a backup should be created
# The file should be located in the the MSDN_data directory
MSDN_INFO_FILE = 'msdn_data.xml'
NEW_SEGMENT_SIZE = 0x800  # size of the new segment
NEW_SEGMENT_NAME = '.msdn'  # name of the new segment
COMMENT_MAX_WIDTH = 40  # maximum column width of comments
MAX_ARG_DESCR_LEN = 600  # maximum string length of argument descriptions
PREVIOUS_INSTR_DELTA = 0xF  # range in where to look for previous instruction
ARG_SEARCH_THRESHOLD = 0xFF  # range in where to look for arguments
# name of enum holding NULL values and description
NULL_ENUM_NAME = 'Null_Enum'


g_logger = logging.getLogger(__name__)


class FailedToExpandSegmentException(Exception):

    def __init__(self, message):
        super(FailedToExpandSegmentException, self).__init__(message)
        self.message = message


class ArgumentNotFoundException(Exception):

    def __init__(self, message):
        super(ArgumentNotFoundException, self).__init__(message)
        self.message = message


class FailedToAppendSegmentException(Exception):

    def __init__(self, message):
        super(FailedToAppendSegmentException, self).__init__(message)
        self.message = message


class RenamingException(Exception):

    def __init__(self, message):
        super(RenamingException, self).__init__(message)
        self.message = message


class NoInputFileException(Exception):

    def __init__(self, message):
        super(NoInputFileException, self).__init__(message)
        self.message = message


def make_import_names_callback(library_calls, library_addr):
    """ Return a callback function used by idaapi.enum_import_names(). """
    def callback(ea, name, ordinal):
        """ Callback function to retrieve code references to library calls. """
        library_calls[name] = []
        library_addr[name] = ea
        for ref in idautils.CodeRefsTo(ea, 0):
            library_calls[name].append(ref)
        return True  # True -> Continue enumeration
    return callback


def get_imports(library_calls, library_addr):
    """ Populate dictionaries with import information. """
    import_names_callback = make_import_names_callback(library_calls,
                                                       library_addr)
    for i in xrange(0, idaapi.get_import_module_qty()):
        idaapi.enum_import_names(i, import_names_callback)


def format_comment(comment_string, width=COMMENT_MAX_WIDTH):
    """ Return UTF encoded string limited to 'width' characters per line. """
    return fill(comment_string, width).encode('utf-8')


def add_fct_descr(ea, function, rep):
    """ Insert a (repeatable) comment describing the function at ea.

    Arguments:
    ea -- effective address where the comment is added
    function -- function object holding data
    rep -- add repeatable comment (True/False)
    """
    descr = format_comment(function.description) + '\n' + \
        format_comment('RETURN VALUE: ' + function.returns)
    # Both functions do not return
    if rep:
        idc.MakeRptCmt(ea, descr)
    else:
        idc.MakeComm(ea, descr)


def get_end_of_last_segment():
    """ Return the last segment's end address. """
    last_ea = 0
    for segment in idautils.Segments():
        if idc.SegEnd(segment) > last_ea:
            last_ea = idc.SegEnd(segment)
    return last_ea


def expand_segment(ea):
    """ Expand last segment so it can hold more MSDN argument information.

    Argument:
    ea -- effective address within last segment
    """
    start = idc.SegStart(ea)
    end = idc.SegEnd(ea)
    if end != get_end_of_last_segment():
        raise FailedToExpandSegmentException('Can only expand last segment.')
    if start == idaapi.BADADDR or end == idaapi.BADADDR:
        raise FailedToExpandSegmentException('Invalid start or end address.')
    new_end = end + NEW_SEGMENT_SIZE / 2
    if not idc.SetSegBounds(ea, start, new_end, idaapi.SEGMOD_KEEP):
        raise FailedToExpandSegmentException('Setting segment bounds failed.')


def get_segment_end_ea(ea):
    """ Return address where next MSDN info can be written to in added
    segment.

    Argument:
    ea -- effective address within added segment where search starts
    """
    addr = ea
    while idc.GetCommentEx(addr, 0) is not None:
        addr = addr + 1
    if addr > idc.SegEnd(ea):
        g_logger.debug('Address {} out of segment bounds. Expanding segment.'
                       .format(hex(addr)))
        try:
            expand_segment(ea)
        except FailedToExpandSegmentException as e:
            g_logger.warning(e.message)
            raise e
    else:
        return addr


def append_segment(segment_name):
    """ Add a new segment to the IDB file and return its starting address.
    Information about function arguments will be stored here. Only works if the
    segment name is not used yet. This does not affect the original binary.

    Arguments:
    segment_name -- the name of the segment to be added
    """
    for segment in idautils.Segments():
        if idc.SegName(segment) == segment_name:
            g_logger.warning('Segment ' + segment_name + ' already exists')
            return idc.SegStart(segment)

    new_segment_start = get_end_of_last_segment()
    g_logger.debug('Adding new segment at 0x%08x' % new_segment_start)
    if not idc.AddSeg(new_segment_start, (new_segment_start+NEW_SEGMENT_SIZE),
                      0, 1, 0, idaapi.scPub) == 1:
        raise FailedToAppendSegmentException('Could not add segment')
    # set new segment's attributes
    if not idc.RenameSeg(new_segment_start, segment_name):
        raise FailedToAppendSegmentException('Could not rename segment')
    if not idc.SetSegClass(new_segment_start, 'DATA'):
        raise FailedToAppendSegmentException('Could not set segment class')
    if not idc.SegAlign(new_segment_start, idc.saRelPara):
        raise FailedToAppendSegmentException('Could not align segment')
    if not idc.SetSegAddressing(new_segment_start, 1):  # 1 -- 32 bit
        raise FailedToAppendSegmentException(
            'Could not set segment addressing')
    return new_segment_start


def name_exists(name):
    """ Return 'True' if name exists in current IDB file. """
    for _, existing_names in idautils.Names():  # generates (addr, name) tuples
        if name in existing_names:
            return True
    return False


def add_arg_descr(function, segment_ea, arg_description_format):
    """ Name address in added segment annotated with argument descriptions.

    Arguments:
    function -- function object
    segment_ea -- start looking for empty byte to annotate from this ea

    Return:
    next possible free address to add information to
    """
    # No arguments
    if len(function.arguments) == 0:
        return segment_ea
    for argument in function.arguments:
        try:
            free_ea = get_segment_end_ea(segment_ea)
        except FailedToExpandSegmentException as e:
            raise e

        fields = {
            "function_name": function.name,
            "function_dll":  function.dll,
            "argument_name": argument.name,
        }
        name = arg_description_format.format(**fields).encode('utf-8')
        if not name_exists(name):
            g_logger.debug(' Adding name {} at {}'.format(name, hex(free_ea)))
            idaapi.set_name(free_ea, name)
            description = argument.description[:MAX_ARG_DESCR_LEN]
            idc.MakeComm(free_ea, format_comment(description))
        else:
            g_logger.debug(' Name %s already exists' % name)
    return (free_ea + 1)


def find_arg_ea(ea_call, arg_name):
    """ Return ea of argument by looking backwards from library function
    call.

    Arguments:
    ea_call -- effective address of call
    arg_name -- the argument name to look for
    """
    # the search for previous instruction/data will stop at the specified
    # address (inclusive)
    prev_instr = idc.PrevHead(ea_call, ea_call - PREVIOUS_INSTR_DELTA)
    while prev_instr > (ea_call - ARG_SEARCH_THRESHOLD) and \
            prev_instr != idaapi.BADADDR:
        # False indicates not to look for repeatable comments
        comment = idc.GetCommentEx(prev_instr, False)
        if comment == arg_name:
            return prev_instr
        prev_instr = idc.PrevHead(
            prev_instr, prev_instr - PREVIOUS_INSTR_DELTA)
    raise ArgumentNotFoundException('  Argument {} not found within threshold'
                                    .format(arg_name))


def add_enums(function):
    """ Add standard enums from parsed MSDN documentation for all imported
    library calls and their arguments.

    Arguments:
    function -- function object
    """
    enum_count = 0
    for argument in function.arguments:
        # Add standard enums
        if not argument.enums:
            g_logger.debug(' No standard constants available for %s' %
                           argument.name)
        else:
            for enum in argument.enums:
                g_logger.debug('  Importing enum %s for argument %s' %
                               (enum, argument.name))
                if idc.Til2Idb(-1, enum) != idaapi.BADADDR:
                    g_logger.debug('  ' + enum + ' ' +
                                   hex(idc.GetEnum(enum)) +
                                   ' added successfully')
                    enum_count = enum_count + 1
                else:
                    g_logger.debug('  Could not add ' + enum)

        if not argument.constants:
            # No constants for this argument
            continue

        argument.name = argument.name.encode('utf-8')
        function.name = function.name.encode('utf-8')

        # Add constant descriptions
        for constant in argument.constants:
            constant.name = constant.name.encode('utf-8')

            if constant.name == 'NULL':
                # Create unique name, so we can add descriptive comment to it
                constant.name = 'NULL_{}_{}'.format(argument.name,
                                                    function.name)
                # Add custom enum for NULL values if it does not exist yet
                enumid = idc.GetEnum(NULL_ENUM_NAME)
                if enumid == idaapi.BADADDR:
                    enumid = idc.AddEnum(-1, NULL_ENUM_NAME, idaapi.hexflag())
                idc.AddConstEx(enumid, constant.name, 0, -1)
                constid = idc.GetConstByName(constant.name)
                idc.SetConstCmt(constid, format_comment(constant.description),
                                False)
            else:
                constid = idc.GetConstByName(constant.name)
                if constid:
                    if idc.SetConstCmt(constid,
                                       format_comment(constant.description),
                                       False):
                        g_logger.debug('    Description added for %s' %
                                       constant.name)
                    else:
                        g_logger.debug('    No description added for %s' %
                                       constant.name)
    return enum_count


def get_bitmasks(enumid):
    """ Return list of bitmasks used in enum. """
    bmasks = []
    bid = idc.GetFirstBmask(enumid)
    while bid != idaapi.BADADDR:
        bmasks.append(bid)
        bid = idc.GetNextBmask(enumid, bid)
    return bmasks


def get_constant_id(enumid, value):
    """ Return id of constant for specific value in enum. """
    constid = idc.GetConstEx(enumid, value, 0, -1)
    if constid != idaapi.BADADDR and not idc.IsBitfield(enumid):
        return constid

    for bm in get_bitmasks(enumid):
        constid = idc.GetConstEx(enumid, value, 0, bm)
        if constid != idaapi.BADADDR:
            return constid
    return idaapi.BADADDR


def rename_constant(arg_ea, fct_name, arg_name, arg_enums):
    """ Rename constants to values from standard enumerations. """
    instruction = idc.GetMnem(arg_ea)
    if instruction == 'push':
        op_num = 0
    elif instruction == 'mov':
        op_num = 1
    else:
        raise RenamingException('Constant: unhandled instruction ' +
                                instruction)

    op_val = idc.GetOperandValue(arg_ea, op_num)
    # NULL
    if op_val == 0:
        targetid = idc.GetConstByName('NULL_{}_{}'.format(arg_name, fct_name))
        serial = 0
        enumid = idc.GetEnum(NULL_ENUM_NAME)
        constid = idc.GetConstEx(enumid, 0, serial, -1)
        while constid != idaapi.BADADDR:
            if constid == targetid:
                idc.OpEnumEx(arg_ea, op_num, enumid, serial)
                return
            serial = serial + 1
            constid = idc.GetConstEx(enumid, 0, serial, -1)

    # All other constants
    op_type = idc.GetOpType(arg_ea, op_num)
    if op_type == idaapi.o_imm:
        # only one choice
        if len(arg_enums) == 1:
            enumid = idc.GetEnum(arg_enums[0])
            idc.OpEnumEx(arg_ea, op_num, enumid, 0)
            return

        for enum in arg_enums:
            enumid = idc.GetEnum(enum)
            constid = get_constant_id(enumid, op_val)
            if constid == idaapi.BADADDR:
                # Not in this enum
                continue
            else:
                # Found the right enum
                idc.OpEnumEx(arg_ea, op_num, enumid, 0)
                return


def rename_argument(ea, function, argument, arg_description_format):
    """ Rename function's argument comment at ea based on config string. """
    fields = {
        "function_name": function.name,
        "function_dll":  function.dll,
        "argument_name": argument.name,
    }
    new_arg = arg_description_format.format(**fields).encode('utf-8')
    idc.MakeComm(ea, new_arg)


def rename_args_and_consts(ref, function, conf_constants_import,
                           conf_arguments_annotate,
                           conf_arg_description_format):
    """ Rename arguments and constants for a function called at 'ref'. """
    for argument in function.arguments:
        try:
            arg_ea = find_arg_ea(ref, argument.name)
        except ArgumentNotFoundException as e:
            g_logger.debug(e.message)
            continue
        if conf_constants_import and argument.enums != []:
            g_logger.debug('  renaming constant {} ({})'.format(argument.name,
                                                                hex(arg_ea)))
            try:
                rename_constant(arg_ea, function.name, argument.name,
                                argument.enums)
            except RenamingException as e:
                g_logger.warning(e)

        if conf_arguments_annotate:
            g_logger.debug('  renaming argument {} ({})'.format(argument.name,
                                                                hex(arg_ea)))
            rename_argument(arg_ea, function, argument,
                            conf_arg_description_format)


def backup_database():
    """ Backup the database to a file similar to IDA's snapshot function. """
    time_string = strftime('%Y%m%d%H%M%S')
    file = idc.GetInputFile()
    if not file:
        raise NoInputFileException('No input file provided')
    input_file = rsplit(file, '.', 1)[0]
    backup_file = '%s_%s.idb' % (input_file, time_string)
    g_logger.info('Backing up database to file ' + backup_file)
    idc.SaveBase(backup_file, idaapi.DBFL_BAK)


def get_data_files(dir):
    """ Return alphabetical sorted list of all found XML data files in
    directory, excluding the main database file (MSDN_INFO_FILE).

    Argument:
    dir -- path where XML data files reside
    """
    data_files = os.listdir(dir)
    if MSDN_INFO_FILE in data_files:
        data_files.remove(MSDN_INFO_FILE)
        return data_files
    else:
        raise IOError('Main database file ' + MSDN_INFO_FILE + ' not found' +
                      ' in ' + dir)


def parse_xml_data_files(msdn_data_dir):
    """ Return dictionary holding function information.

    Arguments:
    msdn_data_dir -- path to the directory storing the XML data files
    """
    functions_map = {}

    # Parse main database file first
    xml_file = os.path.join(msdn_data_dir, MSDN_INFO_FILE)
    functions = xml_parser.parse(xml_file)
    for function in functions:
        functions_map[function.name] = function

    # Parse additional files
    data_files = get_data_files(msdn_data_dir)
    for file in data_files:
        xml_file = os.path.join(msdn_data_dir, file)
        additional_functions = xml_parser.parse(xml_file)

        # Merge functions or add new function
        for a_function in additional_functions:
            if a_function.name in functions_map:
                functions_map[a_function.name].merge(a_function)
            else:
                functions_map[a_function.name] = a_function
    return functions_map


def main(config=None):
    g_logger.info('Starting script execution')

    if CREATE_BACKUP:
        # Backup database before making any changes
        try:
            backup_database()
        except NoInputFileException as e:
            g_logger.warn('Quitting execution: ' + e.message)
            return

    # Default config in case none is provided
    config['arg_description_format'] = '{argument_name}_{function_name}'
    if not config:
        config = {}
        config['functions_annotate'] = True
        config['functions_repeatable_comment'] = False
        config['arguments_annotate'] = True
        config['constants_import'] = True
        config['msdn_data_dir'] = os.path.abspath(os.path.join(idaapi.get_user_idadir(), 'MSDN_data'))

    # Parse XML files and populate dictionary
    msdn_data_dir = config['msdn_data_dir'] 
    if not os.path.exists(msdn_data_dir):
        g_logger.error('Configured msdn data directory does not exist: %s', msdn_data_dir)
        return
    functions_map = parse_xml_data_files(msdn_data_dir)

    # Retrieve all imported functions, store data in dictionaries
    g_logger.debug('Retrieving imported functions')
    library_calls = {}  # maps function_name -> CodeRefTo
    library_addr = {}  # maps function_name -> ea in import table
    get_imports(library_calls, library_addr)

    # Append segment where function argument information will be stored
    try:
        g_logger.debug('Appending new segment %s' % NEW_SEGMENT_NAME)
        free_ea = append_segment(NEW_SEGMENT_NAME)
    except FailedToAppendSegmentException(Exception) as e:
        g_logger.debug(e.message)
        return

    g_logger.debug('Starting annotations')
    functions_not_found = []
    for fct_name, eas in library_calls.iteritems():
        if fct_name not in functions_map:
            # sometimes function info is available, but the import is more
            # specific, e.g., lstrcat vs. lstrcatA/W
            if fct_name[:-1] in functions_map:
                library_addr[fct_name[:-1]] = library_addr[fct_name]
                fct_name = fct_name[:-1]
            elif fct_name[6:] in functions_map:
                # handle mangled names (starting with __imp_)
                library_addr[fct_name[len('__imp_'):]] = library_addr[fct_name]
                fct_name = fct_name[len('__imp_'):]
            else:
                functions_not_found.append(fct_name)
                continue

        g_logger.debug('Working on function %s' % fct_name)
        if config['functions_annotate']:
            # Add function description to import table
            add_fct_descr(library_addr[fct_name],
                          functions_map[fct_name],
                          config['functions_repeatable_comment'])

        if config['constants_import']:
            # Add enums for extracted constant data
            num_added_enums = add_enums(functions_map[fct_name])
            if num_added_enums:
                g_logger.debug(' Added {} ENUMs for {}'.format(num_added_enums,
                                                               fct_name))

        # Add argument description in newly created segment
        free_ea = add_arg_descr(functions_map[fct_name],
                                free_ea, config['arg_description_format'])

        # Rename arguments and constants so they link to set names
        for ref in eas:
            g_logger.debug(' Enhancing argument and constant info for {} ({})'
                           .format(fct_name, hex(ref)))
            rename_args_and_consts(ref, functions_map[fct_name],
                                   config['constants_import'],
                                   config['arguments_annotate'],
                                   config['arg_description_format'])

    # Report
    print '\n======================'
    print 'MSDN Annotator SUMMARY'
    print '======================'
    print ' Functions not found'
    print ' -------------------'
    i = 1
    for f in functions_not_found:
        print '  {}\t{}'.format(i, f)
        i += 1
    print ''

if __name__ == '__main__':
    main()
