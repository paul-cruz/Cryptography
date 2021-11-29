import binascii
from os import P_PGID
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA1
import binascii

# Generate 1024-bit RSA key pair (private + public key)
keyPair = RSA.generate(1024)
pubKey = keyPair.publickey()

pubKeyPEM = pubKey.exportKey()
f = open('mykey.pub','wb')
print(pubKeyPEM)
f.write(pubKeyPEM)
f.close()

f = open('mykey.pem','wb')
f.write(keyPair.export_key('PEM'))
f.close()

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = open('message.txt','rb')
plain_text = open("message.txt", "r")
hash = SHA1.new(msg.read())
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hash)
signer_msg = open('message_c.txt','w')
signer_msg.write(plain_text.read())
signer_msg.close()
plain_text.close()
signer_msg = open('message_c.txt','a')
signer_msg.write(signature.hex())
signer_msg.close()
msg.close()

#B O B
signed_msg = open('message_c.txt','rb')
plain_text = open('message_c.txt', 'r')

f = open('mykey.pub','rb')
content = f.read()
key = RSA.import_key(content)

to_verify = signed_msg.read()
verify_plain = plain_text.read()
print("Hash read: ", to_verify)

#Split message and signature
signature = verify_plain[-256:]
message = verify_plain[:-256]
signature_as_bytes = bytearray. fromhex(signature)
message_as_bytes = str.encode(message)
message_hash = SHA1.new(message_as_bytes)

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
verifier = PKCS115_SigScheme(key)
try:
    verifier.verify(message_hash, signature_as_bytes)
    print("Signature is valid.")
except Exception as e:
    print(e)
    print("Signature is invalid.")
signed_msg.close()
