# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'design.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(549, 439)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(160, 10, 201, 41))
        font = QtGui.QFont()
        font.setFamily("Sans")
        font.setPointSize(24)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 50, 531, 371))
        self.tabWidget.setObjectName("tabWidget")
        self.tb_gen_key = QtWidgets.QWidget()
        self.tb_gen_key.setObjectName("tb_gen_key")
        self.txtUserId = QtWidgets.QLineEdit(self.tb_gen_key)
        self.txtUserId.setGeometry(QtCore.QRect(20, 50, 421, 25))
        self.txtUserId.setObjectName("txtUserId")
        self.btnGenerateRSA = QtWidgets.QPushButton(self.tb_gen_key)
        self.btnGenerateRSA.setGeometry(QtCore.QRect(180, 100, 111, 25))
        self.btnGenerateRSA.setObjectName("btnGenerateRSA")
        self.label_6 = QtWidgets.QLabel(self.tb_gen_key)
        self.label_6.setGeometry(QtCore.QRect(20, 20, 201, 21))
        font = QtGui.QFont()
        font.setFamily("Abyssinica SIL")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setTextFormat(QtCore.Qt.AutoText)
        self.label_6.setObjectName("label_6")
        self.tabWidget.addTab(self.tb_gen_key, "")
        self.tab_sign = QtWidgets.QWidget()
        self.tab_sign.setObjectName("tab_sign")
        self.label_3 = QtWidgets.QLabel(self.tab_sign)
        self.label_3.setGeometry(QtCore.QRect(30, 120, 191, 31))
        font = QtGui.QFont()
        font.setFamily("Abyssinica SIL")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setTextFormat(QtCore.Qt.AutoText)
        self.label_3.setObjectName("label_3")
        self.btnSign = QtWidgets.QPushButton(self.tab_sign)
        self.btnSign.setGeometry(QtCore.QRect(210, 220, 83, 25))
        self.btnSign.setObjectName("btnSign")
        self.txtSign = QtWidgets.QLineEdit(self.tab_sign)
        self.txtSign.setEnabled(False)
        self.txtSign.setGeometry(QtCore.QRect(30, 150, 421, 25))
        self.txtSign.setObjectName("txtSign")
        self.btnBrowseFile = QtWidgets.QPushButton(self.tab_sign)
        self.btnBrowseFile.setGeometry(QtCore.QRect(450, 150, 21, 25))
        self.btnBrowseFile.setObjectName("btnBrowseFile")
        self.txtNewSigner = QtWidgets.QLineEdit(self.tab_sign)
        self.txtNewSigner.setEnabled(False)
        self.txtNewSigner.setGeometry(QtCore.QRect(30, 50, 421, 25))
        self.txtNewSigner.setObjectName("txtNewSigner")
        self.btnBrowseNewSigner = QtWidgets.QPushButton(self.tab_sign)
        self.btnBrowseNewSigner.setGeometry(QtCore.QRect(450, 50, 21, 25))
        self.btnBrowseNewSigner.setObjectName("btnBrowseNewSigner")
        self.label_4 = QtWidgets.QLabel(self.tab_sign)
        self.label_4.setGeometry(QtCore.QRect(30, 20, 191, 31))
        font = QtGui.QFont()
        font.setFamily("Abyssinica SIL")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setTextFormat(QtCore.Qt.AutoText)
        self.label_4.setObjectName("label_4")
        self.tabWidget.addTab(self.tab_sign, "")
        self.tab_verify = QtWidgets.QWidget()
        self.tab_verify.setObjectName("tab_verify")
        self.txtSigned = QtWidgets.QLineEdit(self.tab_verify)
        self.txtSigned.setEnabled(False)
        self.txtSigned.setGeometry(QtCore.QRect(30, 140, 421, 25))
        self.txtSigned.setObjectName("txtSigned")
        self.btnVerify = QtWidgets.QPushButton(self.tab_verify)
        self.btnVerify.setGeometry(QtCore.QRect(200, 220, 83, 25))
        self.btnVerify.setObjectName("btnVerify")
        self.btnBrowseSigned = QtWidgets.QPushButton(self.tab_verify)
        self.btnBrowseSigned.setGeometry(QtCore.QRect(450, 140, 21, 25))
        self.btnBrowseSigned.setObjectName("btnBrowseSigned")
        self.label_2 = QtWidgets.QLabel(self.tab_verify)
        self.label_2.setGeometry(QtCore.QRect(30, 110, 201, 21))
        font = QtGui.QFont()
        font.setFamily("Abyssinica SIL")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setTextFormat(QtCore.Qt.AutoText)
        self.label_2.setObjectName("label_2")
        self.label_5 = QtWidgets.QLabel(self.tab_verify)
        self.label_5.setGeometry(QtCore.QRect(30, 20, 201, 21))
        font = QtGui.QFont()
        font.setFamily("Abyssinica SIL")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setTextFormat(QtCore.Qt.AutoText)
        self.label_5.setObjectName("label_5")
        self.txtActualSigner = QtWidgets.QLineEdit(self.tab_verify)
        self.txtActualSigner.setEnabled(False)
        self.txtActualSigner.setGeometry(QtCore.QRect(30, 50, 421, 25))
        self.txtActualSigner.setObjectName("txtActualSigner")
        self.btnBrowseActualSigner = QtWidgets.QPushButton(self.tab_verify)
        self.btnBrowseActualSigner.setGeometry(QtCore.QRect(450, 50, 21, 25))
        self.btnBrowseActualSigner.setObjectName("btnBrowseActualSigner")
        self.tabWidget.addTab(self.tab_verify, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "RSA signer"))
        self.btnGenerateRSA.setText(_translate("MainWindow", "Generate RSA"))
        self.label_6.setText(_translate("MainWindow", "Enter your user id:"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tb_gen_key), _translate("MainWindow", "Generate RSA Key"))
        self.label_3.setText(_translate("MainWindow", "Select the file to sign:"))
        self.btnSign.setText(_translate("MainWindow", "Sign"))
        self.txtSign.setPlaceholderText(_translate("MainWindow", "Select file"))
        self.btnBrowseFile.setText(_translate("MainWindow", "..."))
        self.txtNewSigner.setText(_translate("MainWindow", "Select the signer key:"))
        self.txtNewSigner.setPlaceholderText(_translate("MainWindow", "Select file"))
        self.btnBrowseNewSigner.setText(_translate("MainWindow", "..."))
        self.label_4.setText(_translate("MainWindow", "Select signer key:"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_sign), _translate("MainWindow", "Sign"))
        self.txtSigned.setPlaceholderText(_translate("MainWindow", "Select file"))
        self.btnVerify.setText(_translate("MainWindow", "Verify"))
        self.btnBrowseSigned.setText(_translate("MainWindow", "..."))
        self.label_2.setText(_translate("MainWindow", "Select the signed file:"))
        self.label_5.setText(_translate("MainWindow", "Select signer key:"))
        self.txtActualSigner.setPlaceholderText(_translate("MainWindow", "Select file"))
        self.btnBrowseActualSigner.setText(_translate("MainWindow", "..."))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_verify), _translate("MainWindow", "Verify"))
