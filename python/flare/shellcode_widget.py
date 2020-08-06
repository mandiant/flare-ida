#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2014 FireEye
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################
#
# IDA QT GUI for Shellode Hash Chooser
#
########################################################################

import sys
import logging
import traceback


from PyQt5 import QtWidgets
from PyQt5 import QtCore 
from PyQt5.QtCore import Qt

# Import the compiled UI module
from . shellcodechooser import Ui_ShellcodeChooser

from . import jayutils

class ShellcodeWidget(QtWidgets.QDialog):
    def __init__(self, dbstore, params, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        try:
            self.logger = jayutils.getLogger('ShellcodeWidget')
            self.logger.debug('Hello debug')
            self.dbstore = dbstore
            self.params = params
            self.configData = {}
            self.ui=Ui_ShellcodeChooser()
            self.ui.setupUi(self)
            self.ui.list_hashNames.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
            self.ui.list_hashNames.currentTextChanged.connect(self.handleTextChange)
            self.ui.buttonBox.accepted.connect(self.storeStateAccepted)
            self.ui.buttonBox.rejected.connect(self.reject)
            self.custom_accepted.connect(self.accept)
            self.ui.cb_dwordArray.stateChanged.connect(self.handleDwordCheckboxChange)
            self.ui.cb_XORSeed.stateChanged.connect(self.handleXORSeedCheckboxChange)
            self.initData()

        except Exception as err:
            self.logger.exception('Error during init: %s', str(err))
    
    custom_accepted = QtCore.pyqtSignal()

    def storeStateAccepted(self):
        self.logger.debug('Storing state on accepted signal')
        self.params.searchDwordArray = self.ui.cb_dwordArray.isChecked()
        self.params.searchPushArgs = self.ui.cb_instrOps.isChecked()
        self.params.createStruct = self.ui.cb_dwordArray.isChecked() and self.ui.cb_createStruct.isChecked()
        self.params.useXORSeed = self.ui.cb_XORSeed.isChecked()
        if (self.params.useXORSeed) and (len(self.ui.text_XORSeed.text()) > 0):
            self.params.XORSeed = int(self.ui.text_XORSeed.text(), 0)
        self.params.useDecompiler = self.ui.cb_useDecompiler.isChecked()
        self.params.hashTypes = [self.hashDict[t.text()] for t in self.ui.list_hashNames.selectedItems()]
        #done storing parameters -> let the outside know we're done
        self.custom_accepted.emit()

    def handleTextChange(self, text):
        try:
            self.logger.debug('Text changed: %s', text)
            self.ui.textBrowse_description.setPlainText(self.configData[text])
        except Exception as err:
            self.logger.exception('Error during text changed: %s', str(err))

    def handleDwordCheckboxChange(self, state):
        try:
            self.ui.cb_createStruct.setEnabled(self.ui.cb_dwordArray.isChecked())
        except Exception as err:
            self.logger.exception('Error during dword check changed: %s', str(err))
    
    def handleXORSeedCheckboxChange(self, state):
        try:
            self.ui.text_XORSeed.setEnabled(self.ui.cb_XORSeed.isChecked())
        except Exception as err:
            self.logger.exception('Error during XOR seed check changed: %s', str(err))

    def initData(self):
        hashTypes = self.dbstore.getAllHashTypes()
        self.hashDict = dict([ (t.hashName, t) for t in hashTypes])

        for hash in hashTypes:
            if hash.hashName in self.configData:
                raise RuntimeError('Duplicate name not allowed')
            self.configData[hash.hashName] = hash.hashCode
            item = QtWidgets.QListWidgetItem(hash.hashName)
            self.ui.list_hashNames.addItem(item)

        self.ui.list_hashNames.setCurrentRow(0)
        self.ui.cb_dwordArray.setCheckState(QtCore.Qt.Checked)
        self.ui.cb_createStruct.setCheckState(QtCore.Qt.Checked)
        self.ui.cb_instrOps.setCheckState(QtCore.Qt.Checked)
        self.ui.cb_XORSeed.setCheckState(QtCore.Qt.Checked)
        self.ui.cb_useDecompiler.setCheckState(QtCore.Qt.Checked)
        return

