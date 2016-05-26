# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'apply_callee_dialog.ui'
#
# Created: Tue Aug 26 12:16:07 2014
#      by: PyQt5-uic 0.2.15 running on PyQt5 1.2.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtWidgets

class Ui_ApplyCalleeDialog(object):
    def setupUi(self, ApplyCalleeDialog):
        ApplyCalleeDialog.setObjectName("ApplyCalleeDialog")
        ApplyCalleeDialog.resize(682, 313)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(ApplyCalleeDialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(ApplyCalleeDialog)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.te_userTypeText = QtWidgets.QPlainTextEdit(ApplyCalleeDialog)
        self.te_userTypeText.setObjectName("te_userTypeText")
        self.horizontalLayout.addWidget(self.te_userTypeText)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pb_useStandardType = QtWidgets.QPushButton(ApplyCalleeDialog)
        self.pb_useStandardType.setObjectName("pb_useStandardType")
        self.horizontalLayout_2.addWidget(self.pb_useStandardType)
        self.pb_useLocalType = QtWidgets.QPushButton(ApplyCalleeDialog)
        self.pb_useLocalType.setObjectName("pb_useLocalType")
        self.horizontalLayout_2.addWidget(self.pb_useLocalType)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.buttonBox = QtWidgets.QDialogButtonBox(ApplyCalleeDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout_2.addWidget(self.buttonBox)

        self.retranslateUi(ApplyCalleeDialog)
        #QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), ApplyCalleeDialog.accept)
        #QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), ApplyCalleeDialog.reject)

        self.buttonBox.accepted.connect(ApplyCalleeDialog.accept)
        self.buttonBox.rejected.connect(ApplyCalleeDialog.reject)

        QtCore.QMetaObject.connectSlotsByName(ApplyCalleeDialog)

    def retranslateUi(self, ApplyCalleeDialog):
        ApplyCalleeDialog.setWindowTitle(QtWidgets.QApplication.translate("ApplyCalleeDialog", "ApplyCalleeType", None))
        self.label.setText(QtWidgets.QApplication.translate("ApplyCalleeDialog", "Enter Type\n"
"Declaration", None))
        self.pb_useStandardType.setText(QtWidgets.QApplication.translate("ApplyCalleeDialog", "Use Standard Type", None))
        self.pb_useLocalType.setText(QtWidgets.QApplication.translate("ApplyCalleeDialog", "Use Local Type", None))

