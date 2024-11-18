import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt(keyfile, infile, outfile):
    with open(keyfile, 'rb') as f:
        key = f.read()
        if len(key) != 32:
            print("The key must be 32 bytes (256 bits) long.")
            sys.exit(1)
    with open(infile, 'rb') as f:
        nonce = f.read(12)
        encrypted = f.read()
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(nonce, encrypted, None)
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)
    with open(outfile, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} keyfile infile outfile")
        sys.exit(1)
    keyfile, infile, outfile = sys.argv[1], sys.argv[2], sys.argv[3]
    decrypt(keyfile, infile, outfile)
