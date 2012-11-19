# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'shellcodechooser.ui'
#
# Created: Fri Nov 16 14:08:46 2012
#      by: pyside-uic 0.2.13 running on PySide 1.1.0
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_ShellcodeChooser(object):
    def setupUi(self, ShellcodeChooser):
        ShellcodeChooser.setObjectName("ShellcodeChooser")
        ShellcodeChooser.resize(450, 249)
        self.verticalLayout_3 = QtGui.QVBoxLayout(ShellcodeChooser)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.list_hashNames = QtGui.QListWidget(ShellcodeChooser)
        self.list_hashNames.setObjectName("list_hashNames")
        self.horizontalLayout.addWidget(self.list_hashNames)
        self.textBrowse_description = QtGui.QTextBrowser(ShellcodeChooser)
        self.textBrowse_description.setObjectName("textBrowse_description")
        self.horizontalLayout.addWidget(self.textBrowse_description)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.groupBox = QtGui.QGroupBox(ShellcodeChooser)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout = QtGui.QVBoxLayout(self.groupBox)
        self.verticalLayout.setSpacing(2)
        self.verticalLayout.setContentsMargins(2, 2, 2, 2)
        self.verticalLayout.setObjectName("verticalLayout")
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setSpacing(2)
        self.gridLayout.setObjectName("gridLayout")
        self.cb_dwordArray = QtGui.QCheckBox(self.groupBox)
        self.cb_dwordArray.setObjectName("cb_dwordArray")
        self.gridLayout.addWidget(self.cb_dwordArray, 0, 0, 1, 1)
        self.cb_createStruct = QtGui.QCheckBox(self.groupBox)
        self.cb_createStruct.setObjectName("cb_createStruct")
        self.gridLayout.addWidget(self.cb_createStruct, 0, 1, 1, 1)
        self.cb_instrOps = QtGui.QCheckBox(self.groupBox)
        self.cb_instrOps.setObjectName("cb_instrOps")
        self.gridLayout.addWidget(self.cb_instrOps, 1, 0, 1, 1)
        self.verticalLayout.addLayout(self.gridLayout)
        self.horizontalLayout_3.addWidget(self.groupBox)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.buttonBox = QtGui.QDialogButtonBox(ShellcodeChooser)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.horizontalLayout_2.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_3.addLayout(self.verticalLayout_2)

        self.retranslateUi(ShellcodeChooser)
        QtCore.QMetaObject.connectSlotsByName(ShellcodeChooser)

    def retranslateUi(self, ShellcodeChooser):
        ShellcodeChooser.setWindowTitle(QtGui.QApplication.translate("ShellcodeChooser", "Shellcode Hash Search", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox.setTitle(QtGui.QApplication.translate("ShellcodeChooser", "Options", None, QtGui.QApplication.UnicodeUTF8))
        self.cb_dwordArray.setText(QtGui.QApplication.translate("ShellcodeChooser", "DWORD Array", None, QtGui.QApplication.UnicodeUTF8))
        self.cb_createStruct.setText(QtGui.QApplication.translate("ShellcodeChooser", "Create Struct", None, QtGui.QApplication.UnicodeUTF8))
        self.cb_instrOps.setText(QtGui.QApplication.translate("ShellcodeChooser", "Instr Operands", None, QtGui.QApplication.UnicodeUTF8))

