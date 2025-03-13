import time
import os
from Crypto.Cipher import AES, Salsa20, ChaCha20
import csv

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

def measure_performance(plaintext, iterations=5):
    results = []
    key = os.urandom(32)  # Llave de 256 bits
    iv = os.urandom(16)   # IV para CBC
    nonce = os.urandom(8) # Nonce para CTR

    for _ in range(iterations):
        # Medir tiempo de cifrado ECB
        start_time = time.time()
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext))
        ecb_encrypt_time = time.time() - start_time

        # Medir tiempo de descifrado ECB
        start_time = time.time()
        decrypted = pkcs7_unpad(cipher.decrypt(ciphertext))
        ecb_decrypt_time = time.time() - start_time

        # Verificar integridad
        assert decrypted == plaintext, "Error en ECB: Los datos descifrados no coinciden con los originales."

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

        # Verificar integridad
        assert decrypted == plaintext, "Error en CBC: Los datos descifrados no coinciden con los originales."

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

        # Verificar integridad
        assert decrypted == plaintext, "Error en CTR: Los datos descifrados no coinciden con los originales."

        results.append({
            "ECB_Encrypt": ecb_encrypt_time,
            "ECB_Decrypt": ecb_decrypt_time,
            "CBC_Encrypt": cbc_encrypt_time,
            "CBC_Decrypt": cbc_decrypt_time,
            "CTR_Encrypt": ctr_encrypt_time,
            "CTR_Decrypt": ctr_decrypt_time,
        })

    return results

def measure_stream_ciphers(plaintext, iterations=5):
    results = []
    key = os.urandom(32)  # Llave de 256 bits
    nonce = os.urandom(8) # Nonce para Salsa20 y ChaCha20

    for _ in range(iterations):
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

        # Verificar integridad
        assert decrypted == plaintext, "Error en Salsa20: Los datos descifrados no coinciden con los originales."

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

        # Verificar integridad
        assert decrypted == plaintext, "Error en ChaCha20: Los datos descifrados no coinciden con los originales."

        results.append({
            "Salsa20_Encrypt": salsa20_encrypt_time,
            "Salsa20_Decrypt": salsa20_decrypt_time,
            "ChaCha20_Encrypt": chacha20_encrypt_time,
            "ChaCha20_Decrypt": chacha20_decrypt_time,
        })

    return results

def calculate_averages(results):
    """
    Calcula los promedios de los tiempos de cifrado y descifrado.
    """
    averages = {}
    for key in results[0].keys():  # Obtener las claves (nombres de las métricas)
        total = sum(result[key] for result in results)  # Sumar todos los valores
        averages[key] = total / len(results)  # Calcular el promedio
    return averages
if __name__ == "__main__":
    plaintext = generate_large_message(100)  # Generar un mensaje de 500 MB
    iterations = 20  # Número de iteraciones para promediar resultados

    # Medir rendimiento de AES
    aes_results = measure_performance(plaintext, iterations)
    aes_averages = calculate_averages(aes_results)  # Calcular promedios
    print("Promedios AES:")
    for key, value in aes_averages.items():
        print(f"{key}: {value:.6f}s")

    # Guardar resultados de AES en CSV


    # Medir rendimiento de cifradores de flujo
    stream_results = measure_stream_ciphers(plaintext, iterations)
    stream_averages = calculate_averages(stream_results)  # Calcular promedios
    print("\nPromedios Cifradores de Flujo:")
    for key, value in stream_averages.items():
        print(f"{key}: {value:.6f}s")

    # Guardar resultados de cifradores de flujo en CSV


    print("\nPruebas completadas. Resultados guardados en archivos CSV.")