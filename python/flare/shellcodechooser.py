# -*- coding: utf-8 -*-
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

# Form implementation generated from reading ui file 'shellcodechooser.ui'
#
# Created: Fri Nov 16 14:08:46 2012
#      by: PyQt5-uic 0.2.13 running on PyQt5 1.1.0
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtWidgets

class Ui_ShellcodeChooser(object):
    def setupUi(self, ShellcodeChooser):
        ShellcodeChooser.setObjectName("ShellcodeChooser")
        ShellcodeChooser.resize(450, 249)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(ShellcodeChooser)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.list_hashNames = QtWidgets.QListWidget(ShellcodeChooser)
        self.list_hashNames.setObjectName("list_hashNames")
        self.horizontalLayout.addWidget(self.list_hashNames)
        self.textBrowse_description = QtWidgets.QTextBrowser(ShellcodeChooser)
        self.textBrowse_description.setObjectName("textBrowse_description")
        self.horizontalLayout.addWidget(self.textBrowse_description)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.groupBox = QtWidgets.QGroupBox(ShellcodeChooser)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout.setSpacing(2)
        self.verticalLayout.setContentsMargins(2, 2, 2, 2)
        self.verticalLayout.setObjectName("verticalLayout")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setSpacing(2)
        self.gridLayout.setObjectName("gridLayout")
        self.cb_dwordArray = QtWidgets.QCheckBox(self.groupBox)
        self.cb_dwordArray.setObjectName("cb_dwordArray")
        self.gridLayout.addWidget(self.cb_dwordArray, 0, 0, 1, 1)
        self.cb_createStruct = QtWidgets.QCheckBox(self.groupBox)
        self.cb_createStruct.setObjectName("cb_createStruct")
        self.gridLayout.addWidget(self.cb_createStruct, 0, 1, 1, 1)
        self.cb_instrOps = QtWidgets.QCheckBox(self.groupBox)
        self.cb_instrOps.setObjectName("cb_instrOps")
        self.gridLayout.addWidget(self.cb_instrOps, 1, 0, 1, 1)
        self.cb_XORSeed = QtWidgets.QCheckBox(self.groupBox)
        self.cb_XORSeed.setObjectName("cb_XORSeed")
        self.gridLayout.addWidget(self.cb_XORSeed, 2, 0, 1, 1)
        self.text_XORSeed = QtWidgets.QLineEdit(self.groupBox)
        self.text_XORSeed.setObjectName("text_XORSeed")
        self.gridLayout.addWidget(self.text_XORSeed, 2, 1, 1, 1)
        self.cb_useDecompiler = QtWidgets.QCheckBox(self.groupBox)
        self.cb_useDecompiler.setObjectName("cb_useDecompiler")
        self.gridLayout.addWidget(self.cb_useDecompiler, 3, 0, 1, 1)
        self.verticalLayout.addLayout(self.gridLayout)
        self.horizontalLayout_3.addWidget(self.groupBox)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.buttonBox = QtWidgets.QDialogButtonBox(ShellcodeChooser)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.horizontalLayout_2.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_3.addLayout(self.verticalLayout_2)

        self.retranslateUi(ShellcodeChooser)
        QtCore.QMetaObject.connectSlotsByName(ShellcodeChooser)

    def retranslateUi(self, ShellcodeChooser):
        print("edited file")
        ShellcodeChooser.setWindowTitle(QtWidgets.QApplication.translate("ShellcodeChooser", "Shellcode Hash Search", None))
        self.groupBox.setTitle(QtWidgets.QApplication.translate("ShellcodeChooser", "Options", None))
        self.cb_dwordArray.setText(QtWidgets.QApplication.translate("ShellcodeChooser", "DWORD Array", None))
        self.cb_createStruct.setText(QtWidgets.QApplication.translate("ShellcodeChooser", "Create Struct", None))
        self.cb_instrOps.setText(QtWidgets.QApplication.translate("ShellcodeChooser", "Instr Operands", None))
        self.cb_useDecompiler.setText(QtWidgets.QApplication.translate("ShellcodeChooser", "Use Decompiler if available", None))
        self.cb_XORSeed.setText(QtWidgets.QApplication.translate("ShellcodeChooser", "Use XOR seed", None))
        self.text_XORSeed.setPlaceholderText("Enter XOR key if hashes have a one time xor applied to them per sample")

