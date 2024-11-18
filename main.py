from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

def pad(s):
    padding = 16 - len(s) % 16
    return s + chr(padding) * padding

def unpad(s):
    padding_value = s[-1]
    if isinstance(padding_value, str):
        padding_value = ord(padding_value)
    if padding_value < 1 or padding_value > 16:
        raise ValueError("Invalid padding.")
    return s[:-padding_value]

def test_pad_unpad(message):
    padded = pad(message)
    unpadded = unpad(padded)
    return message == unpadded

message = "This is a test message."
if test_pad_unpad(message):
    print("Padding and unpadding work correctly.")
else:
    print("Padding and unpadding do not work correctly.")

try:
    bad_padded = "Incorrectly padded data".encode()
    unpad(bad_padded)
except Exception as e:
    print("Error during unpadding:", e)

password = "my_secure_password"
salt = b'secure_salt'
key = PBKDF2(password, salt, dkLen=16)

def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message).encode()
    ciphertext = cipher.encrypt(padded_message)
    return iv, ciphertext

def decrypt_message(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded.decode('utf-8', 'ignore'))
    return decrypted

message = "secret msg"
iv, ciphertext = encrypt_message(message, key)
print("Encrypted message:", ciphertext)

try:
    decrypted_message = decrypt_message(iv, ciphertext, key)
    print("Decrypted message:", decrypted_message)
except Exception as e:
    print("Decryption error:", e)

try:
    wrong_key = bytearray(key)
    wrong_key[0] ^= 1
    decrypted_message_wrong_key = decrypt_message(iv, ciphertext, bytes(wrong_key))
    print("Decrypted with wrong key:", decrypted_message_wrong_key)
except Exception as e:
    print("Decryption error with wrong key:", e)

try:
    wrong_iv = bytearray(iv)
    wrong_iv[0] ^= 1
    decrypted_message_wrong_iv = decrypt_message(bytes(wrong_iv), ciphertext, key)
    print("Decrypted with wrong IV:", decrypted_message_wrong_iv)
except Exception as e:
    print("Decryption error with wrong IV:", e)

with open('cipher.bin', 'wb') as f:
    f.write(iv + ciphertext)
print("Cryptogram saved to 'cipher.bin'.")

with open('cipher.bin', 'rb') as f:
    data = f.read()
iv_from_file = data[:16]
ciphertext_from_file = data[16:]

try:
    decrypted_message_from_file = decrypt_message(iv_from_file, ciphertext_from_file, key)
    print("Decrypted message from file:", decrypted_message_from_file)
except Exception as e:
    print("Decryption error from file:", e)
