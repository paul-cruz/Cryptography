from Utils import Utils
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


class RSASigner:
    RSA_SIGNATURE_SIZE = 128

    def __init__(self, key_path=None, ):
        self.keyPair: RSA.RsaKey = self.import_key(
            key_path) if key_path else None

    def generate_RSA(self, user_id: str) -> str:
        try:

            if not user_id:
                return 'Not user provided'

            keyPair = RSA.generate(1024)
            pubKey = keyPair.publickey()

            pubKeyPEM = pubKey.exportKey()
            f = open(user_id + '.pub', 'wb')
            f.write(pubKeyPEM)
            f.close()

            f = open(user_id + '.pem', 'wb')
            f.write(keyPair.export_key('PEM'))
            f.close()

            return f'Keys generated as {user_id}.pub and {user_id}.pem'
        except Exception as e:
            print(e)
            return 'An error has ocurred'

    def sign_file(self, file_path: str, new_signer_path: str = None) -> str:
        try:
            if not file_path:
                return 'Please enter a file to sign'

            if not self.keyPair and not new_signer_path:
                return 'Please enter a key'

            if not self.keyPair:
                keyPair = self.import_key(new_signer_path)
            else:
                keyPair = self.keyPair

            signed_path = Utils.get_custom_path(file_path, '_s')

            msg = open(file_path, 'rb')
            plain_text = open(file_path, 'rb')
            hash = SHA1.new(msg.read())
            signer = PKCS115_SigScheme(keyPair)
            signature = signer.sign(hash)

            signer_msg = open(signed_path, 'wb')
            signer_msg.write(plain_text.read())
            signer_msg.close()
            plain_text.close()

            signer_msg = open(signed_path, 'ab')
            signer_msg.write(signature)
            signer_msg.close()
            msg.close()

            return f'File signed in {signed_path}'
        except Exception as e:
            print(e)
            return 'An error has ocurred'

    def import_key(self, file_path: str) -> RSA.RsaKey:
        f = open(file_path, 'rb')
        content = f.read()
        key = RSA.import_key(content)
        f.close()
        return key

    def validate_signed_file(self, file_path: str, signer_path: str = None) -> str:
        try:
            if not file_path:
                return 'Please enter a file to validate'

            if not self.keyPair and not signer_path:
                return 'Please enter a key'

            if not self.keyPair:
                key = self.import_key(signer_path)
            else:
                key = self.keyPair

            plain_text = open(file_path, 'rb')
            verify_plain = plain_text.read()

            # Split message and signature
            signature = verify_plain[-Utils.RSA_SIGNATURE_SIZE:]
            message = verify_plain[:-Utils.RSA_SIGNATURE_SIZE]
            message_hash = SHA1.new(message)

            # Verify valid PKCS#1 v1.5 signature (RSAVP1)
            verifier = PKCS115_SigScheme(key)
            result = ''
            try:
                verifier.verify(message_hash, signature)
                result = 'Signature is valid.'
            except Exception as e:
                result = 'Signature is invalid.'
            plain_text.close()

            return result
        except Exception as e:
            print(e)
            return 'An error has ocurred'

    def decrypt(self, ciphertext: str, new_signer_path: str = None) -> str:
        try:
            if not ciphertext:
                return 'Please enter a ciphertext to decrypt'

            if not self.keyPair and not new_signer_path:
                return 'Please enter a key'

            if not self.keyPair:
                keyPair = self.import_key(new_signer_path)
            else:
                keyPair = self.keyPair

            decryptor = PKCS1_OAEP.new(keyPair)
            return decryptor.decrypt(ciphertext)
        except Exception as e:
            print(e)
            return 'An error has ocurred'

    def encrypt(self, message: str, signer_path: str = None) -> str:
        try:
            if not message:
                return 'Please enter a message to encrypt'

            if not self.keyPair and not signer_path:
                return 'Please enter a key'

            if not self.keyPair:
                keyPair = self.import_key(signer_path)
            else:
                keyPair = self.keyPair

            publickey = keyPair.publickey()
            encryptor = PKCS1_OAEP.new(publickey)
            return encryptor.encrypt(message)
        except Exception as e:
            print(e)
            return 'An error has ocurred'
