import base64
import hashlib
import sys

import rsa
import zlib
from Crypto.Cipher import AES, CAST, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os


# def get_symmetric_key(algorithm):
#     if algorithm == AES:
#         return get_random_bytes(16)
#     elif algorithm == CAST:
#         return get_random_bytes(16)


# def get_cipher(algorithm, key):
#     if algorithm == 'AES':
#         return AES.new(key, AES.MODE_CBC)
#     else:
#         # algorithm == 'CAST':
#         return CAST.new(key, CAST.MODE_CBC)
def get_cipher(algorithm, key, iv):
    if algorithm == 'AES':
        return AES.new(key, AES.MODE_CBC, iv)
    elif algorithm == 'CAST':

        return CAST.new(key, CAST.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported algorithm")


# algorithm - aes ili cast5 jer oba koriste 128 bita za kljuc

def encrypt_message(message, public_key, algorithm):
    if isinstance(public_key, bytes):
        public_key = RSA.import_key(public_key)

    symmetric_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    if algorithm == 'CAST':
        iv = get_random_bytes(8)
    cipher = get_cipher(algorithm, symmetric_key, iv)
    if isinstance(message, str):
        message = message.encode('utf-8')
    padded_message = pad(message, cipher.block_size)
    encrypted_message = iv + cipher.encrypt(padded_message)

    #encrypted_key = rsa.encrypt(symmetric_key, public_key)
    print("Simetricni kljuc e: " + str(int.from_bytes(symmetric_key, byteorder='big')))

    encrypted_key = pow(int.from_bytes(symmetric_key, byteorder='big'), public_key.e, public_key.n)
    print("Simetricni kljuc e: " + str(encrypted_key))
    return encrypted_key.to_bytes(length=128, byteorder='big'), encrypted_message


def sign_message(message, private_key):
    if isinstance(private_key, bytes):
        private_key = RSA.import_key(private_key)

    #signature = rsa.sign(message.encode(), private_key, 'SHA-1')
    message_bytes = message.encode() if isinstance(message, str) else message

    sha1_hash = hashlib.sha1(message_bytes).hexdigest()

    potpis = pow(int(sha1_hash, 16), private_key.d, private_key.n)
    print(f'size: {sys.getsizeof(potpis)}')

    return potpis


def compress_message(message):
    compressed_message = zlib.compress(message.encode())
    return compressed_message


def convert_to_radix64(data):
    radix64_data = base64.b64encode(data)
    return radix64_data


# def decrypt_message(encrypted_key, encrypted_message, private_key, algorithm):
#     private_key = RSA.import_key(private_key)
#     print(type(private_key))
#     symmetric_key = rsa.decrypt(encrypted_key, private_key)
#     cipher = get_cipher(symmetric_key)
#     decrypted_message = cipher.decrypt(encrypted_message)
#     return decrypted_message.decode()

def decrypt_message(encrypted_key, encrypted_message, private_key, algorithm):
    print(private_key)
    if isinstance(private_key, bytes):
        private_key = RSA.import_key(private_key)
    print(private_key)
    if private_key.has_private():
        print(private_key)


    #symmetric_key = rsa.decrypt(encrypted_key, private_key)
    symmetric_key = pow(int.from_bytes(encrypted_key, byteorder='big'), private_key.d, private_key.n)
    print("Simetricni kljuc d: "+str(symmetric_key))
    symmetric_key = symmetric_key.to_bytes(length=16, byteorder='big')
    iv = encrypted_message[:16]
    encrypted_data = encrypted_message[16:]

    if algorithm == 'CAST':
        iv = encrypted_message[:8]
        encrypted_data = encrypted_message[8:]

    cipher = get_cipher(algorithm, symmetric_key, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_data), cipher.block_size)
    return decrypted_message


def verify_signature(message, signature, public_key):# ovde puca jer iz nekog razloga prosledi public key kao string
    print(type(public_key))
    if isinstance(public_key, bytes):
        public_key = RSA.import_key(public_key)

    print(type(public_key))
    message_bytes = message.encode() if isinstance(message, str) else message
    sha1_hash = hashlib.sha1(message_bytes).hexdigest()
    hash_from_signature = pow(signature, public_key.e, public_key.n)
    return int(sha1_hash, 16) == hash_from_signature

def decompress_message(compressed_message):
    return zlib.decompress(compressed_message).decode()


def convert_from_radix64(radix64_data):
    return base64.b64decode(radix64_data)


# vrv ce filepath biti kao sto je u kljucevima sa {key_id}
def save_message(filepath, message):
    with open(filepath, "w") as file:
        if isinstance(message, bytes):
            file.write(message.decode('utf-8'))
        else:
            file.write(message)


def delete_message(filepath):
    try:
        os.remove(filepath)
        print(f"File {filepath} deleted successfully.")
    except FileNotFoundError:
        print(f"File {filepath} not found.")
    except Exception as e:
        print(f"Error occurred while trying to delete file {filepath}: {e}")
