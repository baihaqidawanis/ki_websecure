from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- AES ---
def encrypt_aes(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data

def decrypt_aes(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# --- DES ---
def encrypt_des(data, key):
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, DES.block_size))
    return iv + encrypted_data

def decrypt_des(encrypted_data, key):
    iv = encrypted_data[:DES.block_size]
    ciphertext = encrypted_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)

# --- RC4 ---
def encrypt_rc4(data, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

def decrypt_rc4(encrypted_data, key):
    cipher = ARC4.new(key)
    # PASTIKAN ANDA MEMILIKI 'return' DI SINI
    return cipher.decrypt(encrypted_data)