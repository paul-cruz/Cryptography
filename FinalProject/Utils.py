from os import path
from pathlib import Path
from typing import Tuple


class Utils:
    ENCRYPTED_AES_KEY_SIZE = 128
    RSA_SIGNATURE_SIZE = 128

    @staticmethod
    def get_custom_path(original_path: str, extra: str) -> str:
        path_object = Path(original_path)
        return path.join(path_object.parent, path_object.stem + extra + path_object.suffix)

    @staticmethod
    def concat_aes_encrypted_key(encrypted_key: bytes, file_path: str) -> None:
        f = open(file_path, 'ab')
        f.write(encrypted_key)
        f.close()

    @staticmethod
    def divide_encrypted_msg_key(file_path: str) -> Tuple[str, str]:
        aux_path = Utils.get_custom_path(file_path, '_')
        with open(file_path, 'rb') as f:
            content = f.read()
        with open(aux_path, 'wb') as f:
            f.write(content[:-Utils.ENCRYPTED_AES_KEY_SIZE])
        return content[-Utils.ENCRYPTED_AES_KEY_SIZE:], aux_path

    @staticmethod
    def remove_rsa_key_from_encrypted_file(file_path: str) -> Tuple[str, str]:
        aux_path = Utils.get_custom_path(file_path, '_')
        with open(file_path, 'rb') as f:
            content = f.read()
        with open(aux_path, 'wb') as f:
            f.write(content[:-Utils.RSA_SIGNATURE_SIZE])
        return aux_path
