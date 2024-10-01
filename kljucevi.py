import hashlib
import rsa
from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


def encrypt_private_key(private_key, password):
    private_key_bytes = private_key.save_pkcs1()
    salt = get_random_bytes(16)
    iv = get_random_bytes(CAST.block_size)
    key = PBKDF2(password.encode(), salt, dkLen=16, count=1000)
    cipher = CAST.new(key, mode=CAST.MODE_CBC, iv=iv)
    padded_private_key_bytes = pad(private_key_bytes, CAST.block_size)
    encrypted = cipher.encrypt(padded_private_key_bytes)
    return salt + iv + encrypted


def decrypt_private_key(encrypted_private_key, password):
    try:
        salt = encrypted_private_key[:16]
        iv = encrypted_private_key[16:24]
        ciphertext = encrypted_private_key[24:]
        key = PBKDF2(password.encode(), salt, dkLen=16, count=1000)
        cipher = CAST.new(key, mode=CAST.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(decrypted_data, CAST.block_size)
        return unpadded_data
    except ValueError:
        return None


def generate_keys(password, key_size):
    public_key, private_key = rsa.newkeys(key_size)
    encrypted_private_key = encrypt_private_key(private_key, password)

    public_key_bytes = public_key.save_pkcs1()
    hasher = hashlib.sha256()
    hasher.update(public_key_bytes)
    hashed_key = hasher.digest()

    key_id = hashed_key[-8:].hex()
    # da ne bi pravilo milion fajlova
    with open(f"{key_id}_public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open(f"{key_id}_private.pem", "wb") as f:
        f.write(encrypted_private_key)

    return key_id, public_key, encrypted_private_key


def load_public_key(key_id):
    with open(f"{key_id}_public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    return public_key


def load_keys_from_file(key_id, password):
    with open(f"{key_id}_public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open(f"{key_id}_private.pem", "rb") as f:
        encrypted_private_key = f.read()

    decrypted_private_key = decrypt_private_key(encrypted_private_key, password)
    if decrypted_private_key is None:
        raise ValueError("Decryption failed. Check your password.")

    private_key = rsa.PrivateKey.load_pkcs1(decrypted_private_key)

    crypted_again = encrypt_private_key(private_key, password)

    return public_key, crypted_again
