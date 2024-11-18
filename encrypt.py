
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(keyfile, infile, outfile):
    with open(keyfile, 'rb') as f:
        key = f.read()
        if len(key) != 32:
            print("The key must be 32 bytes (256 bits) long.")
    with open(infile, 'rb') as f:
        data = f.read()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    encrypted = aesgcm.encrypt(nonce, data, None)
    with open(outfile, 'wb') as f:
        f.write(nonce + encrypted)

if __name__ == "__main__":
    encrypt(keyfile, infile, outfile)
