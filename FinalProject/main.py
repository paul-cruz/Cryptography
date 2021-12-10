from PyQt5 import QtWidgets
from design import Ui_MainWindow
from Utils import Utils
from RSA import RSASigner
from AES import AESCipher
import sys
sys.path.append('.')


class Window(QtWidgets.QMainWindow):

    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Binding submit buttons
        self.ui.btnSign.clicked.connect(self.handle_sign_file)
        self.ui.btnEncrypt.clicked.connect(self.handle_encrypt)
        self.ui.btnDecrypt.clicked.connect(self.handle_decrypt)
        self.ui.btnEncryptSign.clicked.connect(self.handle_encrypt_sign)
        self.ui.btnGenerateRSA.clicked.connect(self.handle_rsa_generate)
        self.ui.btnVerify.clicked.connect(self.handle_validate_signed_file)
        self.ui.btnDecryptVerify.clicked.connect(self.handle_decrypt_validate)

        # Binding select file buttons
        self.ui.btnBrowseFile.clicked.connect(self.select_file)
        self.ui.btnBrowseSigned.clicked.connect(self.select_file)
        self.ui.btnBrowseNewSigner.clicked.connect(self.select_file)
        self.ui.btnBrowseMessageFile.clicked.connect(self.select_file)
        self.ui.btnBrowseActualSigner.clicked.connect(self.select_file)
        self.ui.btnBrowseTargetPublicKey.clicked.connect(self.select_file)
        self.ui.btnBrowseTargetPrivateKey.clicked.connect(self.select_file)
        self.ui.btnBrowseNewSignerToEncrypt.clicked.connect(self.select_file)
        self.ui.btnBrowseMessageFileToEncrypt.clicked.connect(self.select_file)
        self.ui.btnBrowseEncryptedMessageFile.clicked.connect(self.select_file)
        self.ui.btnBrowseMessageFileToDecrypt.clicked.connect(self.select_file)
        self.ui.btnBrowseActualSignerToDecrypt.clicked.connect(
            self.select_file)
        self.ui.btnBrowseTargetPublicKeyToEncrypt.clicked.connect(
            self.select_file)
        self.ui.btnBrowseTargetPrivateKeyToDecrypt.clicked.connect(
            self.select_file)

    def select_file(self) -> None:
        id = self.sender().objectName()
        txt = None

        if id == 'btnBrowseFile':
            txt = self.ui.txtSign
        elif id == 'btnBrowseSigned':
            txt = self.ui.txtSigned
        elif id == 'btnBrowseNewSigner':
            txt = self.ui.txtNewSigner
        elif id == 'btnBrowseMessageFile':
            txt = self.ui.txtMessageToEncrypt
        elif id == 'btnBrowseActualSigner':
            txt = self.ui.txtActualSigner
        elif id == 'btnBrowseTargetPublicKey':
            txt = self.ui.txtTargetPublicKey
        elif id == 'btnBrowseTargetPrivateKey':
            txt = self.ui.txtTargetPrivateKey
        elif id == 'btnBrowseNewSignerToEncrypt':
            txt = self.ui.txtSignerPrivateKey
        elif id == 'btnBrowseMessageFileToEncrypt':
            txt = self.ui.txtMessageToEncryptSign
        elif id == 'btnBrowseEncryptedMessageFile':
            txt = self.ui.txtMessageToDecrypt
        elif id == 'btnBrowseMessageFileToDecrypt':
            txt = self.ui.txtMessageToDecryptVerify
        elif id == 'btnBrowseActualSignerToDecrypt':
            txt = self.ui.txtSignerPublicKey
        elif id == 'btnBrowseTargetPublicKeyToEncrypt':
            txt = self.ui.txtTargetPublicKeyEncrypt
        elif id == 'btnBrowseTargetPrivateKeyToDecrypt':
            txt = self.ui.txtTargetPrivateKeyDecrypt

        txt.setText(
            QtWidgets.QFileDialog.getOpenFileName()[0])

    def handle_rsa_generate(self) -> None:
        try:
            userID = self.ui.txtUserId.text()
            signer = RSASigner()
            result = signer.generate_RSA(userID)
            self.custom_dialog('RSA Result', result)
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def handle_sign_file(self) -> None:
        try:
            new_signer_path = self.ui.txtNewSigner.text()
            file_path = self.ui.txtSign.text()
            if not file_path or not new_signer_path:
                self.error('Please select all the parameters')
                return

            signer = RSASigner(new_signer_path)
            result = signer.sign_file(file_path)
            self.custom_dialog('RSA Result', result)
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def handle_validate_signed_file(self) -> None:
        try:
            signer_path = self.ui.txtActualSigner.text()
            file_path = self.ui.txtSigned.text()
            if not file_path or not signer_path:
                self.error('Please select all the parameters')
                return

            signer = RSASigner(signer_path)
            result = signer.validate_signed_file(file_path)
            self.custom_dialog('RSA Result', result)
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def custom_dialog(self, title: str, msg: str) -> None:
        dialog = QtWidgets.QMessageBox
        dialog.about(self, title, msg)

    def handle_encrypt(self) -> None:
        try:
            file_path = self.ui.txtMessageToEncrypt.text()
            signer_key_path = self.ui.txtTargetPublicKey.text()

            if not file_path or not signer_key_path:
                self.error('Please select all the parameters')
                return

            signer = RSASigner(signer_key_path)
            cipher = AESCipher()
            key = cipher.key
            encrypted_key = signer.encrypt(key)
            out_path = cipher.encrypt_file(file_path, key)
            Utils.concat_aes_encrypted_key(encrypted_key, out_path)
            self.custom_dialog(
                'Encrypt Result', f'Encrypted file generated as {out_path}')
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def handle_decrypt(self) -> None:
        try:
            file_path = self.ui.txtMessageToDecrypt.text()
            signer_key_path = self.ui.txtTargetPrivateKey.text()

            if not file_path or not signer_key_path:
                self.error('Please select all the parameters')
                return

            signer = RSASigner(signer_key_path)
            cipher = AESCipher()
            key, encrypted_file_path = Utils.divide_encrypted_msg_key(
                file_path)
            key = signer.decrypt(key)
            out_path = cipher.decrypt_file(encrypted_file_path, key)

            self.custom_dialog(
                'Encrypt Result', f'Decrypted file generated as {out_path}')
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def handle_encrypt_sign(self) -> None:
        try:
            file_path = self.ui.txtMessageToEncryptSign.text()
            signer_key_path = self.ui.txtSignerPrivateKey.text()
            target_key_path = self.ui.txtTargetPublicKeyEncrypt.text()

            if not file_path or not signer_key_path and not target_key_path:
                self.error('Please select all the parameters')
                return

            signer = RSASigner(signer_key_path)
            cipher = AESCipher()
            key = cipher.key
            encrypted_key = signer.encrypt(key)
            out_path = cipher.encrypt_file(file_path, key)
            Utils.concat_aes_encrypted_key(encrypted_key, out_path)

            result = signer.sign_file(out_path)
            self.custom_dialog('Result', f'Encrypted and {result}')
        except Exception as e:
            self.custom_dialog('Error', str(e))

    def handle_decrypt_validate(self) -> None:
        try:
            file_path = self.ui.txtMessageToDecryptVerify.text()
            signer_key_path = self.ui.txtSignerPublicKey.text()
            target_key_path = self.ui.txtTargetPrivateKeyDecrypt.text()

            if not file_path or not signer_key_path and not target_key_path:
                self.error('Please select all the parameters')
                return

            verifier = RSASigner(signer_key_path)
            result = verifier.validate_signed_file(file_path)
            if result == 'Signature is invalid.':
                self.custom_dialog('RSA Result', result)
                return

            new_file = Utils.remove_rsa_key_from_encrypted_file(file_path)

            descipher = RSASigner(target_key_path)
            cipher = AESCipher()
            key, encrypted_file_path = Utils.divide_encrypted_msg_key(
                new_file)
            key = descipher.decrypt(key)
            out_path = cipher.decrypt_file(encrypted_file_path, key)

            self.custom_dialog(
                'Encrypt Result', f'Decrypted file generated as {out_path}')
        except Exception as e:
            self.custom_dialog('Error', str(e))


app = QtWidgets.QApplication([])

application = Window()

application.show()

sys.exit(app.exec())
