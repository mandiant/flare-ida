# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'struct_typer_widget.ui'
#
# Created: Wed Aug 13 10:16:29 2014
#      by: pyside-uic 0.2.15 running on PySide 1.2.1
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(502, 364)
        self.verticalLayout_2 = QtGui.QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.rb_useStackFrame = QtGui.QRadioButton(Dialog)
        self.rb_useStackFrame.setObjectName("rb_useStackFrame")
        self.buttonGroup = QtGui.QButtonGroup(Dialog)
        self.buttonGroup.setObjectName("buttonGroup")
        self.buttonGroup.addButton(self.rb_useStackFrame)
        self.verticalLayout.addWidget(self.rb_useStackFrame)
        self.rb_useStruct = QtGui.QRadioButton(Dialog)
        self.rb_useStruct.setChecked(True)
        self.rb_useStruct.setObjectName("rb_useStruct")
        self.buttonGroup.addButton(self.rb_useStruct)
        self.verticalLayout.addWidget(self.rb_useStruct)
        self.listWidget = QtGui.QListWidget(Dialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.MinimumExpanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.listWidget.sizePolicy().hasHeightForWidth())
        self.listWidget.setSizePolicy(sizePolicy)
        self.listWidget.setObjectName("listWidget")
        self.verticalLayout.addWidget(self.listWidget)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.checkBox = QtGui.QCheckBox(Dialog)
        self.checkBox.setObjectName("checkBox")
        self.horizontalLayout.addWidget(self.checkBox)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.lineEdit = QtGui.QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout_2.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "StructTyper", None, QtGui.QApplication.UnicodeUTF8))
        self.rb_useStackFrame.setText(QtGui.QApplication.translate("Dialog", "Current Stack Frame", None, QtGui.QApplication.UnicodeUTF8))
        self.rb_useStruct.setText(QtGui.QApplication.translate("Dialog", "Structure", None, QtGui.QApplication.UnicodeUTF8))
        self.checkBox.setText(QtGui.QApplication.translate("Dialog", "Prefix RegEx", None, QtGui.QApplication.UnicodeUTF8))

