# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'apply_callee_dialog.ui'
#
# Created: Mon Aug 25 09:30:32 2014
#      by: pyside-uic 0.2.15 running on PySide 1.2.1
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_ApplyCalleeDialog(object):
    def setupUi(self, ApplyCalleeDialog):
        ApplyCalleeDialog.setObjectName("ApplyCalleeDialog")
        ApplyCalleeDialog.resize(682, 313)
        self.verticalLayout_2 = QtGui.QVBoxLayout(ApplyCalleeDialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(ApplyCalleeDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.te_userTypeText = QtGui.QPlainTextEdit(ApplyCalleeDialog)
        self.te_userTypeText.setObjectName("te_userTypeText")
        self.horizontalLayout.addWidget(self.te_userTypeText)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pb_useStandardType = QtGui.QPushButton(ApplyCalleeDialog)
        self.pb_useStandardType.setObjectName("pb_useStandardType")
        self.horizontalLayout_2.addWidget(self.pb_useStandardType)
        self.pb_useLocalType = QtGui.QPushButton(ApplyCalleeDialog)
        self.pb_useLocalType.setObjectName("pb_useLocalType")
        self.horizontalLayout_2.addWidget(self.pb_useLocalType)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.buttonBox = QtGui.QDialogButtonBox(ApplyCalleeDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout_2.addWidget(self.buttonBox)

        self.retranslateUi(ApplyCalleeDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), ApplyCalleeDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), ApplyCalleeDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(ApplyCalleeDialog)

    def retranslateUi(self, ApplyCalleeDialog):
        ApplyCalleeDialog.setWindowTitle(QtGui.QApplication.translate("ApplyCalleeDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("ApplyCalleeDialog", "Enter Type\n"
"Declaration", None, QtGui.QApplication.UnicodeUTF8))
        self.pb_useStandardType.setText(QtGui.QApplication.translate("ApplyCalleeDialog", "Use Standard Type", None, QtGui.QApplication.UnicodeUTF8))
        self.pb_useLocalType.setText(QtGui.QApplication.translate("ApplyCalleeDialog", "Use Local Type", None, QtGui.QApplication.UnicodeUTF8))

