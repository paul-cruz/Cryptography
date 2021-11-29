import sys
from os import path
from pathlib import Path
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from design import Ui_MainWindow
from PyQt5 import QtWidgets


class Window(QtWidgets.QMainWindow):

    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.btnSign.clicked.connect(self.sign_file)
        self.ui.btnBrowseFile.clicked.connect(self.select_file)
        self.ui.btnGenerateRSA.clicked.connect(self.generate_RSA)
        self.ui.btnBrowseSigned.clicked.connect(self.select_file)
        self.ui.btnBrowseNewSigner.clicked.connect(self.select_file)
        self.ui.btnVerify.clicked.connect(self.validate_signed_file)
        self.ui.btnBrowseActualSigner.clicked.connect(self.select_file)

    def select_file(self):
        id = self.sender().objectName()
        txt = None

        if id == 'btnBrowseActualSigner':
            txt = self.ui.txtActualSigner
        elif id == 'btnBrowseFile':
            txt = self.ui.txtSign
        elif id == 'btnBrowseNewSigner':
            txt = self.ui.txtNewSigner
        elif id == 'btnBrowseSigned':
            txt = self.ui.txtSigned

        txt.setText(
            QtWidgets.QFileDialog.getOpenFileName()[0])

    def generate_RSA(self):
        try:
            userID = self.ui.txtUserId.text()

            if not userID:
                self.error('Enter a valid userID')
                return

            keyPair = RSA.generate(1024)
            pubKey = keyPair.publickey()

            pubKeyPEM = pubKey.exportKey()
            f = open(userID + '.pub', 'wb')
            f.write(pubKeyPEM)
            f.close()

            f = open(userID + '.pem', 'wb')
            f.write(keyPair.export_key('PEM'))
            f.close()

            self.success(f'Keys generated as {userID}.pub and {userID}.pem')
        except Exception as e:
            self.error(e)

    def sign_file(self):
        try:
            new_signer_path = self.ui.txtNewSigner.text()
            file_path = self.ui.txtSign.text()
            if not file_path or not new_signer_path:
                self.error('Please select all the parameters')
                return

            keyPair = self.import_key(new_signer_path)
            signed_path = self.get_signed_path(file_path)

            msg = open(file_path, 'rb')
            plain_text = open(file_path, 'r')
            hash = SHA1.new(msg.read())
            signer = PKCS115_SigScheme(keyPair)
            signature = signer.sign(hash)

            signer_msg = open(signed_path, 'w')
            signer_msg.write(plain_text.read())
            signer_msg.close()
            plain_text.close()

            signer_msg = open(signed_path, 'a')
            signer_msg.write(signature.hex())
            signer_msg.close()
            msg.close()

            self.success(f'File signed in {signed_path}')
        except Exception as e:
            self.error(e)

    def import_key(self, file_path: str) -> RSA.RsaKey:
        f = open(file_path, 'rb')
        content = f.read()
        key = RSA.import_key(content)
        f.close()
        return key

    def get_signed_path(self, original_path: str) -> str:
        path_object = Path(original_path)
        return path.join(path_object.parent, path_object.stem + '_c' + path_object.suffix)

    def validate_signed_file(self):
        try:
            signer_path = self.ui.txtActualSigner.text()
            file_path = self.ui.txtSigned.text()
            if not file_path or not signer_path:
                self.error('Please select all the parameters')
                return

            signed_msg = open(file_path, 'rb')
            plain_text = open(file_path, 'r')

            key = self.import_key(signer_path)
            verify_plain = plain_text.read()

            # Split message and signature
            signature = verify_plain[-256:]
            message = verify_plain[:-256]
            signature_as_bytes = bytearray. fromhex(signature)
            message_as_bytes = str.encode(message)
            message_hash = SHA1.new(message_as_bytes)

            # Verify valid PKCS#1 v1.5 signature (RSAVP1)
            verifier = PKCS115_SigScheme(key)
            result = ''
            try:
                verifier.verify(message_hash, signature_as_bytes)
                result = 'Signature is valid.'
            except Exception as e:
                result = 'Signature is invalid.'

            QtWidgets.QMessageBox.about(self, 'Validation result',
                                        result)
            signed_msg.close()
        except Exception as e:
            self.error(e)

    def error(self, msg: str):
        dialog = QtWidgets.QMessageBox
        dialog.about(self, 'Error',
                     msg)

    def success(self, msg: str):
        dialog = QtWidgets.QMessageBox
        dialog.about(self, 'Success',
                     msg)


app = QtWidgets.QApplication([])

application = Window()

application.show()

sys.exit(app.exec())
