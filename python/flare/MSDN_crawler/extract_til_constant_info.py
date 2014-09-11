"""
Obtain matchups between a constant name and the standard enum IDA Pro uses.

Authors: William Ballenthin, Moritz Raabe
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

import re
import sys
import os
import logging
import subprocess

g_logger = logging.getLogger("til_extractor")


def show_usage():
    print 'Usage:',
    print sys.argv[0] + ' <path to tilib> <til directory>'


def main(tilib_exe, til_dir):
    logging.basicConfig(level=logging.WARN)

    if not os.path.isfile(tilib_exe):
        g_logger.warn(tilib_exe + ' is not a file')
        return False
    if not os.path.isdir(til_dir):
        g_logger.warn(til_dir + ' is not a directory')
        return False

    const_pattern = re.compile("([0-9A-Fa-f]{8}) ([0-9A-Fa-f]{8}) +([A-Za-z0-9_]+) ([A-Za-z0-9_]+)")
    ignored_enum_names = set(["int", "unsigned", "const", "UINT", "void", "struct", "__int16", "char"])

    for til_file in os.listdir(til_dir):
        til_file = os.path.join(til_dir, til_file)
        g_logger.debug("Will process til file: %s", til_file)
        if not os.path.isfile(til_file):
            continue

        try:
            output = subprocess.check_output([tilib_exe, "-l", til_file],
                                             shell=True,
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            g_logger.warn("Error calling tilib.exe with %s -- %s", til_file, e)
            # Not all files can be parsed correctly
            continue

        enums = {}  # dict of (enum_name:string, enum_def:dict of (constant_name:string, constant_value:int))
        for line in output.split("\n"):
            if "__stdcall" in line:
                continue
            if "__cdecl" in line:
                continue
            if "__fastcall" in line:
                continue

            m = const_pattern.match(line)
            if not m:
                continue

            constant_value = int(m.group(2), 0x10)
            enum_name = m.group(3)
            constant_name = m.group(4)

            # our simple parsing of the text output isn't very smart, so we get
            # some typedefs, too try to ignore those, on a best effort basis
            if enum_name in ignored_enum_names:
                continue

            g_logger.debug("%s", line)
            g_logger.debug("  value: %s", hex(constant_value))
            g_logger.debug("  enum_name: %s", enum_name)
            g_logger.debug("  constant_name: %s", constant_name)

            enum = enums.get(enum_name, {})
            if constant_name not in enum:
                enum[constant_name] = constant_value
            enums[enum_name] = enum

    return_data = {}  # dict of (constant_name:string, enum_name:string)
    for enum_name, enum in enums.iteritems():
        for constant_name, constant_value in enum.iteritems():
            return_data[constant_name] = enum_name
    return return_data

if __name__ == '__main__':
    main()
