import time
import os
from Crypto.Cipher import AES
from Crypto.Cipher import Salsa20, ChaCha20

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def generate_large_message(size_in_mb=2):
    base_text = b"""
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
    Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    """ 

    target_size = size_in_mb * 1024 * 1024  # Convert MB to bytes (2MB = 2,097,152 bytes)
    repetitions = target_size // len(base_text) + 1  # Repeat enough times

    return (base_text * repetitions)[:target_size]  


def measure_performance():
    plaintext = generate_large_message(100)
    
    key = os.urandom(32)  # Llave de 256 bits
    iv = os.urandom(16)   # IV para CBC
    nonce = os.urandom(8) # Nonce para CTR

    # Medir tiempo de cifrado ECB
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintext))
    ecb_encrypt_time = time.time() - start_time

    # Medir tiempo de descifrado ECB
    start_time = time.time()
    decrypted = pkcs7_unpad(cipher.decrypt(ciphertext))
    ecb_decrypt_time = time.time() - start_time

    # Medir tiempo de cifrado CBC
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7_pad(plaintext))
    cbc_encrypt_time = time.time() - start_time

    # Medir tiempo de descifrado CBC
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = pkcs7_unpad(cipher.decrypt(ciphertext))
    cbc_decrypt_time = time.time() - start_time

    # Medir tiempo de cifrado CTR
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    ctr_encrypt_time = time.time() - start_time

    # Medir tiempo de descifrado CTR
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    ctr_decrypt_time = time.time() - start_time

    print(f"ECB - Cifrado: {ecb_encrypt_time:.6f}s, Descifrado: {ecb_decrypt_time:.6f}s")
    print(f"CBC - Cifrado: {cbc_encrypt_time:.6f}s, Descifrado: {cbc_decrypt_time:.6f}s")
    print(f"CTR - Cifrado: {ctr_encrypt_time:.6f}s, Descifrado: {ctr_decrypt_time:.6f}s")



    from Crypto.Cipher import Salsa20, ChaCha20

def measure_stream_ciphers():
    plaintext = b"Este es un mensaje de prueba para medir el rendimiento."
    key = os.urandom(32)  # Llave de 256 bits
    nonce = os.urandom(8) # Nonce para Salsa20 y ChaCha20

    # Medir tiempo de cifrado Salsa20
    start_time = time.time()
    cipher = Salsa20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    salsa20_encrypt_time = time.time() - start_time

    # Medir tiempo de descifrado Salsa20
    start_time = time.time()
    cipher = Salsa20.new(key=key, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    salsa20_decrypt_time = time.time() - start_time

    # Medir tiempo de cifrado ChaCha20
    start_time = time.time()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    chacha20_encrypt_time = time.time() - start_time

    # Medir tiempo de descifrado ChaCha20
    start_time = time.time()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    chacha20_decrypt_time = time.time() - start_time

    print(f"Salsa20 - Cifrado: {salsa20_encrypt_time:.6f}s, Descifrado: {salsa20_decrypt_time:.6f}s")
    print(f"ChaCha20 - Cifrado: {chacha20_encrypt_time:.6f}s, Descifrado: {chacha20_decrypt_time:.6f}s")


if __name__ == "__main__":
    measure_stream_ciphers()
    measure_performance()
