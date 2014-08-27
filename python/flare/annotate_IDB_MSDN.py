"""
IDAPython script providing an user interface for setting the configuration for
annotating database files with MSDN information.

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

import sys
import logging
import traceback
import ConfigParser
from ConfigParser import SafeConfigParser
from PySide import QtGui
from PySide import QtCore
from PySide.QtCore import Qt

idaapi.require("IDB_MSDN_Annotator")


CONFIG_FILE = 'MSDN_annotations.cfg'


g_logger = logging.getLogger(__name__)

def getDefaultMsdnDataDir():
    return os.path.abspath(os.path.join(idaapi.get_user_idadir(), 'MSDN_data'))

class MSDNAnnotationDialog(QtGui.QDialog):

    def read_config(self):
        config = {}
        if not self.config_parser.has_section('Functions') or \
           not self.config_parser.has_section('Arguments') or \
           not self.config_parser.has_section('Constants'):
            # Create default
            self.config_parser.add_section('Functions')
            self.config_parser.add_section('Arguments')
            self.config_parser.add_section('Constants')
            config['functions_annotate'] = True
            config['functions_repeatable_comment'] = False
            config['arguments_annotate'] = True
            config['constants_import'] = True
            config['msdn_data_dir'] = getDefaultMsdnDataDir()

        else:
            # Read existing
            config['functions_annotate'] = self.config_parser.getboolean('Functions', 'annotate')
            config['functions_repeatable_comment'] = self.config_parser.getboolean('Functions', 'repeatable_comment')
            config['arguments_annotate'] = self.config_parser.getboolean('Arguments', 'annotate')
            config['constants_import'] = self.config_parser.getboolean('Constants', 'import')
            try:
                config['msdn_data_dir'] = self.config_parser.get('Constants', 'msdn_data_dir')
            except ConfigParser.NoOptionError:
                config['msdn_data_dir'] = getDefaultMsdnDataDir()

        return config

    def save_config(self):
        self.config_parser.set('Functions', 'annotate', str(self.chkFunctionsAnnotate.isChecked()))
        self.config_parser.set('Functions', 'repeatable_comment', str(self.chkFuntcsRepeatable.isChecked()))
        self.config_parser.set('Arguments', 'annotate', str(self.chkArgumentsAnnotate.isChecked()))
        self.config_parser.set('Constants', 'import', str(self.chkConstantsImport.isChecked()))
        self.config_parser.set('Constants', 'msdn_data_dir', str(self.dirText.text()) )

        with open(self.file_path, 'wb') as conffile:
            self.config_parser.write(conffile)

    def change_image(self):
        funct = self.chkFunctionsAnnotate.isChecked() and \
            self.chkFuntcsRepeatable.isChecked()
        image = "{}-{}-{}.png".format(int(funct),
                                          int(self.chkArgumentsAnnotate
                                              .isChecked()),
                                          int(self.chkConstantsImport
                                              .isChecked()))
        img_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'IDB_MSDN_Annotator', 'img'))
        self.pic.setPixmap(QtGui.QPixmap(os.path.join(img_path, image)))

    def on_select_dir(self):
        msdnDir = QtGui.QFileDialog.getExistingDirectory(caption='Select directory containing MSDN XML Database')
        if len(msdnDir) != 0:
            self.dirText.setText(msdnDir)

    def toggle_option(self):
        disable = not self.chkFunctionsAnnotate.isChecked()
        self.chkFuntcsRepeatable.setDisabled(disable)
        self.change_image()

    def on_ok_button(self):
        #test the msdn data dir

        msdnpath = os.path.join(self.dirText.text(), IDB_MSDN_Annotator.MSDN_INFO_FILE)
        if not os.path.exists(msdnpath):
            g_logger.info('Error - no msdn info file: %s', msdnpath)
            ret = QtGui.QMessageBox.warning(self, 'MSDN Info Not Found', 'The file %s was not found in the specified MSDN Data Directory' % IDB_MSDN_Annotator.MSDN_INFO_FILE, QtGui.QMessageBox.Ok)
            #self.done(QtGui.QDialog.Rejected)
            return

        self.done(QtGui.QDialog.Accepted)
        g_logger.info('Saving config')
        self.save_config()
        config = self.read_config()
        idaapi.set_script_timeout(1)
        IDB_MSDN_Annotator.main(config)
        idaapi.set_script_timeout(0)

    def set_form_values(self):
        # Set values according to configuration file
        if self.config['functions_annotate']:
            self.chkFunctionsAnnotate.setCheckState(QtCore.Qt.Checked)
            if self.config['functions_repeatable_comment']:
                self.chkFuntcsRepeatable.setCheckState(QtCore.Qt.Checked)
        else:
            self.chkFuntcsRepeatable.setDisabled(True)
            self.chkFuntcsRepeatable.setCheckState(QtCore.Qt.Unchecked)
        if self.config['arguments_annotate']:
            self.chkArgumentsAnnotate.setCheckState(QtCore.Qt.Checked)
        if self.config['constants_import']:
            self.chkConstantsImport.setCheckState(QtCore.Qt.Checked)
        self.dirText.setText(self.config['msdn_data_dir'])

    def populate_form(self):
        layout = QtGui.QVBoxLayout()

        # Functions
        layout1 = QtGui.QVBoxLayout()
        groupBox = QtGui.QGroupBox('Markup Options')
        self.chkFunctionsAnnotate = QtGui.QCheckBox("Annotate function names"
                                                    " (see note)")
        layout1.addWidget(self.chkFunctionsAnnotate)
        self.chkFuntcsRepeatable = QtGui.QCheckBox("Use repeatable comments "
                                                   "for function name "
                                                   "annotations")
        layout1.addWidget(self.chkFuntcsRepeatable)

        # Arguments
        self.chkArgumentsAnnotate = QtGui.QCheckBox("Annotate function "
                                                    "arguments (see note)")
        layout1.addWidget(self.chkArgumentsAnnotate)

        # Constants
        self.chkConstantsImport = QtGui.QCheckBox("Rename constants")
        layout1.addWidget(self.chkConstantsImport)

        groupBox.setLayout(layout1)
        layout.addWidget(groupBox)

        #MSDN data dir
        hlayout = QtGui.QHBoxLayout()
        self.selectDirButton = QtGui.QPushButton('...')
        self.selectDirButton.clicked.connect(self.on_select_dir)
        hlayout.addWidget(self.selectDirButton)
        self.dirText = QtGui.QLineEdit()
        self.dirText.setReadOnly(True)
        hlayout.addWidget(self.dirText)
        groupBox = QtGui.QGroupBox('MSDN Data Directory')
        groupBox.setLayout(hlayout)
        layout.addWidget(groupBox)

        # Toggle
        self.chkFunctionsAnnotate.clicked.connect(self.toggle_option)
        self.chkFuntcsRepeatable.clicked.connect(self.change_image)
        self.chkArgumentsAnnotate.clicked.connect(self.change_image)
        self.chkConstantsImport.clicked.connect(self.change_image)

        self.set_form_values()

        info_string = "Note: Annotating functions and/or arguments allows " \
                      "you to hover\nthe respective element in order to " \
                      "show its description."
        layout.addWidget(QtGui.QLabel(info_string))

        # Buttons
        button_ok = QtGui.QPushButton('&OK')
        button_ok.setDefault(True)
        button_ok.clicked.connect(self.on_ok_button)
        #button_ok.clicked.connect(self.close)
        layout.addWidget(button_ok)
        button_cancel = QtGui.QPushButton('&Cancel')
        button_cancel.clicked.connect(self.close)
        layout.addWidget(button_cancel)

        # Image
        self.pic = QtGui.QLabel()
        self.pic.setGeometry(0, 0, 663, 203)
        self.change_image()

        # Layout right
        layout_r = QtGui.QVBoxLayout()
        #layout_r.addWidget(QtGui.QLabel("Annotation preview"))
        layout_r.addWidget(self.pic)
        groupBox = QtGui.QGroupBox('Annotation preview')
        groupBox.setLayout(layout_r)

        # Setup layouts
        h_layout = QtGui.QHBoxLayout()
        h_layout.addLayout(layout)
        #h_layout.addLayout(layout_r)
        h_layout.addWidget(groupBox)
        self.setLayout(h_layout)

    def __init__(self, parent=None):
        self._logger = logging.getLogger(__name__ + '.' +
                                         self.__class__.__name__)
        self._logger.debug('Starting UI')
        QtGui.QDialog.__init__(self, parent, QtCore.Qt.WindowSystemMenuHint |
                               QtCore.Qt.WindowTitleHint)
        self.setWindowTitle("MSDN Annotations Configuration")

        # Parse configuration file to dictionary
        self.file_path = os.path.abspath(os.path.join(idaapi.get_user_idadir(), CONFIG_FILE))
        self.config_parser = SafeConfigParser()
        self.config_parser.read(self.file_path)
        self.config = self.read_config()

        self.populate_form()


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)

    dlg = MSDNAnnotationDialog()
    # Disable script timeout -> otherwise cancel script dialog pops up
    oldTo = idaapi.set_script_timeout(0)
    dlg.exec_()
    # Restore the timeout
    idaapi.set_script_timeout(oldTo)
    g_logger.debug('UI closed')
