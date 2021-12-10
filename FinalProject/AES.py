import os
from Utils import Utils
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher:
    ENCRYPTED_AES_KEY_SIZE = 128

    def __init__(self):
        self.mode = AES.MODE_CBC
        self.key = os.urandom(16)

    def pad(self, s: bytes) -> bytes:
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message: bytes, key: bytes) -> bytes:
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, self.mode, iv)
        message = self.pad(message)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, self.mode, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def encrypt_file(self, file_path: str, key: bytes) -> str:
        with open(file_path, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, key)
        out_path = Utils.get_custom_path(file_path, '_c')
        with open(out_path, 'wb') as fo:
            fo.write(enc)
        return out_path

    def decrypt_file(self, file_path: str, key: bytes) -> str:
        with open(file_path, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, key)
        out_path = Utils.get_custom_path(file_path, '_d')
        with open(out_path, 'wb') as fo:
            fo.write(dec)
        return out_path
