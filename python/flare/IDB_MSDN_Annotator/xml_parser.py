"""
Parse XML file containing MSDN documentation.

Authors: Moritz Raabe, William Ballenthin
Copyright 2014 Mandiant, A FireEye Company

TODO: License

Based on zynamics' code at
https://code.google.com/p/zynamics/source/browse/?repo=msdn-ida-plugin
"""

import os.path
import sys
import xml.sax.handler
import itertools
import logging


class ParsingException(Exception):

    def __init__(self, message):
        super(ParsingException, self).__init__(message)
        self.message = message


class Argument:

    def __init__(self):
        self.name = ""
        self.description = ""
        self.constants = []
        self.enums = []
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("(%s, %s): %s" % (self.name, self.enums, self.description)).encode("ISO-8859-1")

    def __repr__(self):
        return self.__str__()

    def get_constant(self, name):
        for const in self.constants:
            if const.name == name:
                return const
        return None
        
    def merge(self, new_argument):
        if self.name != new_argument.name:
            return

        if new_argument.description:
            self._logger.debug('   Overwriting argument description')
            self.description = new_argument.description
        if new_argument.constants:
            for constant in new_argument.constants:
                current_const = self.get_constant(constant.name)
                if not current_const:
                    # Constant not in list yet
                    self._logger.debug('   Adding new constant ' + constant.name)
                    self.constants.append(constant)
                    continue
                # Constant possibly needs to be updated
                current_const.merge(constant)
        if new_argument.enums:
            self._logger.debug('   Merging argument enums, resulting in [' + \
                               ', '.join(self.enums) + ']')
            self.enums += new_argument.enums


class Constant:

    def __init__(self):
        self.name = ""
        self.value = ""
        self.description = ""
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("(%s, %s)" % (self.name, self.value)).encode("ISO-8859-1")

    def __repr__(self):
        return self.__str__()

    def merge(self, new_constant):
        if self.name != new_constant.name:
            return

        self._logger.debug('   Working on constant ' + self.name)
        if new_constant.value:
            self._logger.debug('    Overwriting constant value')
            self.value = new_constant.value
        if new_constant.description:
            self._logger.debug('    Overwriting constant description')
            self.description = new_constant.description

class Function:

    def __init__(self):
        self.name = ""
        self.dll = ""
        self.description = ""
        self.arguments = []
        self.returns = ""
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def __str__(self):
        return ("%s -- %s" % (self.name, self.arguments)).encode("ISO-8859-1")

    def __repr__(self):
        return self.__str__()

    def get_argument(self, name):
        for arg in self.arguments:
            if arg.name == name:
                return arg
        return None
        
    def merge(self, new_function):
        """
        Merge two function objects. Information found in the second function
        instance will overwrite previously obtained data.

        Argument:
        new_function -- function object that will overwrite previous data
        """
        if self.name != new_function.name:
            return
        
        self._logger.debug('Merging function ' + self.name)
        if new_function.dll:
            self._logger.debug(' Overwriting DLL info')
            self.dll = new_function
        if new_function.description:
            self._logger.debug(' Overwriting function description')
            self.description = new_function.description
        if new_function.arguments:
            for arg in new_function.arguments:
                self._logger.debug('  Working on argument ' + arg.name)
                current_arg = self.get_argument(arg.name)
                if not current_arg:
                    # Argument not in list yet
                    self._logger.debug('  Adding argument ' + arg.name + ' to arguments')
                    self.arguments.append(arg)
                    continue
                # Argument possibly needs to be updated
                current_arg.merge(arg)
        if new_function.returns:
            self._logger.debug(' Overwriting function return value')
            self.returns = new_function.returns


class FunctionHandler(xml.sax.handler.ContentHandler):
    c = itertools.count()
    IN_FUNCTION = next(c)
    IN_FUNCTION_NAME = next(c)
    IN_DLL = next(c)
    IN_FUNCTION_DESCRIPTION = next(c)
    IN_ARGUMENTS = next(c)
    IN_ARGUMENT = next(c)
    IN_ARGUMENT_NAME = next(c)
    IN_ARGUMENT_DESCRIPTION = next(c)
    IN_RETURNS = next(c)
    IN_CONSTANTS = next(c)
    IN_CONSTANT = next(c)
    IN_CONSTANT_NAME = next(c)
    IN_CONSTANT_VALUE = next(c)
    IN_CONSTANT_DESCRIPTION = next(c)

    def __init__(self):
        self.inTitle = 0
        self.mapping = {}
        self.current_step = 0
        self.functions = []
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def startElement(self, name, attributes):
        if name == "msdn":
            pass
        elif name == "functions":
            pass
        elif name == "function":
            self.current_step = FunctionHandler.IN_FUNCTION
            self.function = Function()
        elif self.current_step == FunctionHandler.IN_FUNCTION and name == "name":
            self.current_step = FunctionHandler.IN_FUNCTION_NAME
        elif self.current_step == FunctionHandler.IN_ARGUMENT and name == "name":
            self.current_step = FunctionHandler.IN_ARGUMENT_NAME
        elif name == "dll":
            self.current_step = FunctionHandler.IN_DLL
        elif self.current_step == FunctionHandler.IN_FUNCTION and name == "description":
            self.current_step = FunctionHandler.IN_FUNCTION_DESCRIPTION
        elif self.current_step == FunctionHandler.IN_ARGUMENT and name == "description":
            self.current_step = FunctionHandler.IN_ARGUMENT_DESCRIPTION
        elif self.current_step == FunctionHandler.IN_CONSTANT and name == "name":
            self.current_step = FunctionHandler.IN_CONSTANT_NAME
        elif self.current_step == FunctionHandler.IN_CONSTANT and name == "value":
            self.current_step = FunctionHandler.IN_CONSTANT_VALUE
        elif self.current_step == FunctionHandler.IN_CONSTANT and name == "description":
            self.current_step = FunctionHandler.IN_CONSTANT_DESCRIPTION
        elif name == "arguments":
            self.current_step = FunctionHandler.IN_ARGUMENTS
        elif name == "argument":
            self.current_step = FunctionHandler.IN_ARGUMENT
            self.current_argument = Argument()
        elif self.current_step == FunctionHandler.IN_CONSTANTS and name == "constant":
            self.current_step = FunctionHandler.IN_CONSTANT
            self.current_constant = Constant()
        elif name == "constants":
            self.current_step = FunctionHandler.IN_CONSTANTS
            self.current_argument.enums = []
            if "enums" in attributes.getNames():
                enums = attributes.getValue('enums').encode('utf-8')
                if enums:
                    self.current_argument.enums = enums.split(',')
        elif name == "returns":
            self.current_step = FunctionHandler.IN_RETURNS
        else:
            self._logger.warning('Error START: ' + name)
            raise ParsingException('start')

    def characters(self, data):
        if self.current_step == FunctionHandler.IN_FUNCTION_NAME:
            self.function.name = self.function.name + data
        elif self.current_step == FunctionHandler.IN_DLL:
            self.function.dll = self.function.dll + data
        elif self.current_step == FunctionHandler.IN_FUNCTION_DESCRIPTION:
            self.function.description = self.function.description + data
        elif self.current_step == FunctionHandler.IN_ARGUMENT_NAME:
            self.current_argument.name = self.current_argument.name + data
        elif self.current_step == FunctionHandler.IN_ARGUMENT_DESCRIPTION:
            self.current_argument.description = self.current_argument.description + \
                data
        elif self.current_step == FunctionHandler.IN_RETURNS:
            self.function.returns = self.function.returns + data
        elif self.current_step == FunctionHandler.IN_CONSTANT_NAME:
            self.current_constant.name = self.current_constant.name + data
        elif self.current_step == FunctionHandler.IN_CONSTANT_VALUE:
            self.current_constant.value = self.current_constant.value + data
        elif self.current_step == FunctionHandler.IN_CONSTANT_DESCRIPTION:
            self.current_constant.description = self.current_constant.description + \
                data

    def endElement(self, name):
        if name in ["functions", "msdn"]:
            pass
        elif name == "function":
            self.functions.append(self.function)
        elif self.current_step in [FunctionHandler.IN_ARGUMENT_NAME, FunctionHandler.IN_ARGUMENT_DESCRIPTION]:
            self.current_step = FunctionHandler.IN_ARGUMENT
        elif self.current_step in [FunctionHandler.IN_CONSTANT_NAME, FunctionHandler.IN_CONSTANT_VALUE, FunctionHandler.IN_CONSTANT_DESCRIPTION]:
            self.current_step = FunctionHandler.IN_CONSTANT
        elif name in ["name", "dll", "description", "arguments", "returns", "constants"]:
            self.current_step = FunctionHandler.IN_FUNCTION
        elif name == "argument":
            self.current_step = FunctionHandler.IN_ARGUMENT
            self.function.arguments.append(self.current_argument)
        elif name == "constant":
            self.current_step = FunctionHandler.IN_CONSTANTS
            self.current_argument.constants.append(self.current_constant)
        else:
            self._logger.warning('Error END: ' + name)
            raise ParsingException('end')


g_logger = logging.getLogger(__name__)
            
def parse(xmlfile):
    """
    Return parsed MSDN information.

    Argument:
    xmlfile -- xml data file storing the MSDN information
    """
    g_logger.info('Starting parsing ' + xmlfile)
    parser = xml.sax.make_parser()
    try:
        handler = FunctionHandler()
    except ParsingException as e:
        g_logger.warning(e.message)
        return None # TODO critical?
    parser.setContentHandler(handler)
    parser.parse(xmlfile)
    return handler.functions
