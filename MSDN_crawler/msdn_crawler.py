"""
Crawler to extract information from the MSDN documentation about functions,
arguments and constants. The data gets stored into a XML database file which
is used by the MSDN annotations plug-in for IDA Pro.

Run in Windows Command Prompt
"C:\Python27\python.exe" msdn_crawler.py <path to extracted MSDN doc> \
<path to tilib.exe> <path to til files>

For example:
C:\Python27\python.exe" msdn_crawler.py "C:\extracted_doc" \
"C:\Program Files (x86)\IDA 6.6\tilib.exe" \
"C:\Program Files (x86)\IDA 6.6\til\pc"

Authors: Moritz Raabe, William Ballenthin
Copyright 2014 Mandiant, A FireEye Company

This script is based on zynamics msdn-crawler (Copyright (C) 2010) to be found
at http://github.com/zynamics/msdn-crawler

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import os
import sys
import re
import csv
import logging
from pprint import pprint

from BeautifulSoup import BeautifulSoup
import extract_til_constant_info

MSDN_INFO_FILE = 'msdn_data.xml'


g_logger = logging.getLogger(__name__)


def strip_html(string):
    r1 = re.compile("<.*?>")
    r2 = re.compile(" +")
    return r2.sub(" ", r1.sub("", string).replace("&nbsp;", " ")
                  .replace("\t", " ").replace("&)", ")")
                  .replace("&#8211;", "-").replace("&#8212;", "-")
                  .replace("&#160;", " "))


def parse_old_style(file, content):
    m = re.search(
        "<ph:apidata><api>(.*)</api><name>(.*)</name></ph:apidata>", content)
    if m:
        dll = m.group(1).lower()
        function_name = m.group(2)

        m = re.search("<span></span><P>(.*?)</P>", content)
        if m:
            description = strip_html(m.group(1))
        else:
            g_logger.debug("Error: Could not retrieve function description"
                             " from file %s" % file)
            return None

        m = re.search("<P CLASS=\"clsRef\">Parameters</P><BLOCKQUOTE>(.*?)"
                      "</BLOCKQUOTE>", content)
        if m:
            argument_names = re.findall("<DT><I>(.*?)</I>", m.group(1))
            descriptions = [strip_html(string) for string in
                            re.findall("<DD>(.*?)</DD>", m.group(1))]
            arguments = zip(argument_names, descriptions)
        else:
            # It's possible to have functions without arguments
            arguments = []

        # Return value
        m = re.search("<P CLASS=\"clsRef\">Return Value</P><BLOCKQUOTE>"
                      "<P>(.*?)</P>", content)
        if m:
            return_value = strip_html(m.group(1))
        else:
            # If something has no return value it's not a function.
            return None

        g_logger.debug("Found function %s!%s (old style)"
                       % (dll, function_name))

        # TODO import constants into parse_old_style
        # return_list.append((dll_name.lower(), function_name, description, arguments, constant_data, return_value))
        constant_data = None
        constant_enum = ""
        return [(dll, function_name, description, arguments, constant_data,
                constant_enum, return_value)]
    else:
        return None


def parse_new_style(file, content, const_enum):
    # Check for > not for /> because some docs are broken
    api_types = re.findall(
        "<MSHelp:Attr Name=\"APIType\" Value=\"(.*?)\"[ /]*>", content)
    if api_types in ([], ["Schema"], ["UserDefined"], ["HeaderDef"],
                     ["MOFDef"], ["NA"], ["LibDef"]):
        return None

    if api_types not in ([], ["COM"], ["DllExport"]):
        g_logger.debug("API Type: ", ' '.join(api_types))

    # Check for > not for /> because some docs are broken
    function_names = re.findall(
        "<MSHelp:Attr Name=\"APIName\" Value=\"(.*?)\"[ /]*>", content)

    if function_names:
        # indicates which standard enum(s) IDA knows for this argument
        constant_enum = {}

        # DLL
        # Check for > not for /> because some docs are broken
        dll_names = re.findall(
            "<MSHelp:Attr Name=\"APILocation\" Value=\"(.*?)\"[ /]*>", content)
        if not dll_names:
            return None

        # Description
        m = re.search("<meta name=\"Description\" content=\"(.*?)\"/>",
                      content, re.IGNORECASE)
        if m:
            description = strip_html(m.group(1))
        else:
            g_logger.debug("Error: Could not retrieve function description"
                             " from file %s" % file)
            return None

        # Arguments
        m = re.search("<P CLASS=\"clsRef\">Parameters</P>"
                      "<BLOCKQUOTE>(.*?)</BLOCKQUOTE>", content)
        if m:
            argument_names = re.findall("<DT><I>(.*?)</I>", m.group(1))
            descriptions = [strip_html(string) for string in
                            re.findall("<DD>(.*?)</DD>", m.group(1))]
            arguments = zip(argument_names, descriptions)
        else:
            m = re.search("<h3>Parameters</h3><dl>(.*?)</dl><h3>", content)
            if m:
                argument_names = re.findall("<dt><i>(.*?)</i>", m.group(1))
                argument_names = [
                    arg_name.replace("<i>", "") for arg_name in argument_names]
                # Get descriptions for all arguments
                descriptions = re.findall("<dd>(.*?)</dd>", m.group(1))
                stripped_descriptions = [
                    strip_html(descr) for descr in descriptions]
                arguments = zip(argument_names, stripped_descriptions)

                # Find constants and store them in dictionary
                constant_data = {}
                for i in range(0, len(argument_names)):
                                        # Are there descriptions for each
                                        # argument?
                    if len(descriptions) != len(argument_names):
                        constant_data = None
                        break

                        # Look in "Parameters" section for constants from
                        # tables that include name, hex value, and description
                    constant_names = re.findall(
                        "<dl><dt>(.*?)</dt>", descriptions[i])
                    constant_names = [strip_html(unicode(c, 'utf-8'))
                                      .encode('utf-8') for c in constant_names]
                    parsed_html = BeautifulSoup(descriptions[i])
                    constant_descriptions = [strip_html(string.encode('ascii'))
                                             .encode('utf-8') for string in
                                             parsed_html.find_all(width='60%')]

                    # Change name to NULL, TODO correct?
                    for k in range(0, len(constant_names)):
                        if constant_names[k] == '0':
                            constant_names[k] = 'NULL'

                    if len(constant_names) != len(constant_descriptions):
                        g_logger.debug('constants count mismatch',
                                       argument_names[i], len(constant_names),
                                       len(constant_descriptions),
                                       '\n\tfct:', function_names)

                    # Only add entries for arguments with constant data
                    if constant_names:
                        constant_data[argument_names[i]] = zip(
                            constant_names, constant_descriptions)
                    found_enums = []
                    for name in constant_names:
                        #pprint(const_enum)
                        enum_name = get_enum_for_constant(name, const_enum)
                        if enum_name and enum_name != 'MACRO_NULL':
                            g_logger.debug(
                                'found constant in database', name, enum_name)
                            found_enums.append(enum_name)
                        else:
                            g_logger.debug(name, 'not found in database')
                    if constant_names and found_enums:
                        found_enums = list(set(found_enums))  # make unique
                        constant_enum[argument_names[i]] = ','.join(
                            found_enums)
                        g_logger.debug('final constant data from database',
                                       argument_names[i], constant_enum)
            else:
                # Functions without arguments
                arguments = []
                constant_data = None

        # Return value
        m = re.search("<h3>Return Value</h3><p>(.*?)</p>", content)
        if m:
            return_value = strip_html(m.group(1))
        else:
            # If something has no return value it is not a function.
            return None

        # The blacklist holds functions we identified where the crawler
        # currently does not extract the correct information
        blacklist = ['RegLoadKeyA', 'RegLoadKeyW', 'RegLoadMUIString',
                     'RegLoadMUIStringA', 'RegLoadMUIStringW',
                     'RegNotifyChangeKeyValue', 'RegOpenCurrentUser',
                     'RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyEx',
                     'RegOpenKeyExA', 'RegOpenKeyExW', 'RegOpenKeyTransacted',
                     'RegOpenKeyTransactedA', 'RegOpenKeyTransactedW',
                     'RegOverridePredefKey']
        return_list = []
        for dll_name in dll_names:
            for function_name in function_names:
                # Skip blacklisted functions
                if function_name in blacklist:
                    continue
                g_logger.debug("Found function %s!%s (new style)" %
                               (dll_name.lower(), function_name))
                return_list.append((dll_name.lower(), function_name,
                                   description, arguments, constant_data,
                                   constant_enum, return_value))
        return return_list
    else:
        # No functions found
        return None


def get_enum_for_constant(constant_name, const_enum):
    if constant_name in const_enum:
        return const_enum[constant_name]
    else:
        return False


def parse_file(file, const_enum):
    g_logger.debug("Parsing %s" % file)

    try:
        text_file = open(file, "r")
    except IOError as e:
        g_logger.warn("Could not read file " + file + e.message)
        return None
    content = text_file.read().translate(None, "\r\n")
    text_file.close()

    if content.find("ph:apidata") != -1:
        return parse_old_style(file, content)
    elif content.find("<MSHelp:Attr Name=\"APIName\"") != -1:
        return parse_new_style(file, content, const_enum)
    else:
        return None


def to_xml(results):
    xml_string = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
    xml_string = xml_string + "<msdn>\n"
    xml_string = xml_string + "<functions>\n"

    #for (dll, fct, _, args, cd, _, _) in results:
    #    print '\t', dll, fct
    #    print '\t\t', args
    #    print '\t\t\t', cd

    for (dll_name, function_name, description, arguments, constant_data,
         constant_enum, return_value) in results:
        xml_string = xml_string + "\t<function>\n"
        xml_string = xml_string + "\t\t<name>%s</name>\n" % function_name
        xml_string = xml_string + "\t\t<dll>%s</dll>\n" % dll_name
        xml_string = xml_string + \
            "\t\t<description>%s</description>\n" % description

        xml_string = xml_string + "\t\t<arguments>\n"

        for (argument_name, argument_description) in arguments:
            xml_string = xml_string + "\t\t\t<argument>\n"
            xml_string = xml_string + \
                "\t\t\t\t<name>%s</name>\n" % argument_name
            xml_string = xml_string + \
                "\t\t\t\t<description>%s</description>\n" \
                % argument_description

            # add information about identified constants for this argument
            if constant_data and argument_name in constant_data.keys():
                argument_name, function_name
                if argument_name in constant_enum.keys():
                    xml_string = xml_string + "\t\t\t\t<constants enums=\"" + \
                        constant_enum[argument_name] + "\">\n"
                else:
                    xml_string = xml_string + "\t\t\t\t<constants>\n"
                for (constant_name, constant_description) in constant_data[argument_name]:
                    xml_string = xml_string + "\t\t\t\t\t<constant>\n"
                    xml_string = xml_string + "\t\t\t\t\t\t<name>%s</name>\n" \
                        % constant_name.replace('<b>', '').replace('</b>', '').replace('<i>', '').replace('</i>', '').replace('<a>', '').replace('</a>', '')
                    xml_string = xml_string + \
                        "\t\t\t\t\t\t<description>%s</description>\n" \
                        % constant_description
                    xml_string = xml_string + "\t\t\t\t\t</constant>\n"

                xml_string = xml_string + "\t\t\t\t</constants>\n"

            xml_string = xml_string + "\t\t\t</argument>\n"

        xml_string = xml_string + "\t\t</arguments>\n"

        xml_string = xml_string + "\t\t<returns>%s</returns>\n" % return_value
        xml_string = xml_string + "\t</function>\n"

    xml_string = xml_string + "</functions>\n"
    xml_string = xml_string + "</msdn>"

    return xml_string


def exclude_dir(directory):
    exclude_dirs = ["\\1033\\html", "\\1033\\workshop"]
    for exclude_dir in exclude_dirs:
        if directory.find(exclude_dir) != -1:
            return True
    return False


def parse_files(msdn_directory, tilib_exe, til_dir):
    """
    Return parsed information from MSDN documentation
    """
    file_counter = 0
    results = []
    const_enum = {}

    const_enum = extract_til_constant_info.main(tilib_exe, til_dir)
    if not const_enum:
        g_logger.warn('Could not extract information from TIL files')
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG)

    for root, dirs, files in os.walk(msdn_directory):
        for file in files:
            if exclude_dir(root):
                continue

            if file.endswith('htm'):
                file_counter += 1
                result = parse_file(os.path.join(root, file), const_enum)
                if result:
                    results.append(result)
    return (file_counter, results)


def show_usage():
    print 'Usage:',
    print sys.argv[0] + ' <path to msdn> <path to tilib> <til directory>'


def main():
    print "MSDN crawler based on zynamics msdn-crawler - Copyright 2010"
    
    if len(sys.argv) < 4:
        show_usage()
        sys.exit(1)
    
    if "-v" in sys.argv:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARN)

    msdn_directory = sys.argv[1]
    tilib_exe = os.path.abspath(sys.argv[2])
    til_dir = os.path.abspath(sys.argv[3])

    (file_counter, results) = parse_files(msdn_directory, tilib_exe, til_dir)
    results = sum(results, [])

    print "Parsed %d files" % file_counter
    print "Extracted information about %d functions" % len(results)

    parent_dir = os.path.abspath(
                 os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                              os.pardir))
    
    xml_file = open(os.path.join(parent_dir, "MSDN_data", "msdn_data_nn.xml"), "w")
    xml_file.write(to_xml(results))
    xml_file.close()

if __name__ == "__main__":
    main()
