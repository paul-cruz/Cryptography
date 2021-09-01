import sys
from design import Ui_MainWindow
from PyQt5 import QtWidgets
from cryptography.fernet import Fernet


class Window(QtWidgets.QMainWindow):

    def __init__(self):
        super(Window, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.btnBrowseEncrypt.clicked.connect(self.select_encrypt_file)
        self.ui.btnBrowseDecrypt.clicked.connect(self.select_decrypt_file)
        self.ui.btnEncrypt.clicked.connect(self.encrypt)
        self.ui.btnDecrypt.clicked.connect(self.decrypt)

    def select_encrypt_file(self):
        self.ui.txtEncrypt.setText(QtWidgets.QFileDialog.getOpenFileName()[0])

    def select_decrypt_file(self):
        self.ui.txtDecrypt.setText(QtWidgets.QFileDialog.getOpenFileName()[0])

    def encrypt(self):
        dialog = QtWidgets.QMessageBox
        file_path = self.ui.txtEncrypt.text()
        encrypted_file_path = file_path[:-4] + "_C.txt"

        if(not file_path or file_path[-4:] != ".txt"):
            dialog.about(self, "Encryption Failed",
                         "File not selected or invalid format!")
            return

        key = Fernet.generate_key()
        f = Fernet(key)
        with open(file_path, "rb") as file:
            file_data = file.read()
            encrypted_data = f.encrypt(file_data)
            with open(encrypted_file_path, "wb") as file:
                file.write(encrypted_data)

        dialog.about(self, "Encryption completed",
                     f"Result file path: {encrypted_file_path}\nKey: {key}\n")

    def decrypt(self):
        dialog = QtWidgets.QMessageBox
        encrypted_file_path = self.ui.txtDecrypt.text()
        decrypted_file_path = encrypted_file_path[:-4] + "_D.txt"
        decryption_key = self.ui.txtKey.text()

        if(not encrypted_file_path or encrypted_file_path[-4:] != ".txt" or not decryption_key):
            dialog.about(self, "Decryption Failed",
                         "File not selected or invalid format or key!")
            return

        f = Fernet(decryption_key)
        with open(encrypted_file_path, "rb") as file:
            encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)
            with open(decrypted_file_path, "wb+") as file:
                file.write(decrypted_data)

        dialog.about(self, "Decryption completed",
                     f"Result file path: {decrypted_file_path}")


app = QtWidgets.QApplication([])

application = Window()

application.show()

sys.exit(app.exec())
