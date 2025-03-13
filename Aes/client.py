import socket
import sys
import os
from Crypto.Cipher import AES


# Load MAIN_KEY
def load_main_key(file_path):
    """Carga la MAIN_KEY desde un archivo binario."""
    if not os.path.exists(file_path):
        print(f"[CLIENTE] Archivo {file_path} no encontrado.")
        return None
    with open(file_path, "rb") as f:
        main_key = f.read()
    print("[CLIENTE] MAIN_KEY cargada:", main_key.hex())
    return main_key

HOST = '10.20.56.176'
PORT = 6000


# Funciones auxiliares para manejo de mensajes

def recv_exact(sock, num_bytes):
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_message(sock):
    length_data = recv_exact(sock, 4)
    if not length_data:
        return None
    msg_len = int.from_bytes(length_data, 'big')
    if msg_len == 0:
        return b''
    return recv_exact(sock, msg_len)

def send_message(sock, data):
    msg_len = len(data)
    sock.sendall(msg_len.to_bytes(4, 'big'))
    sock.sendall(data)


# Funciones de cifrado y descifrado

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_cbc_decrypt(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(dec_padded)


# Parsear las sub-llaves recibidas en binario
def parse_subkeys(blob):
    """
    Convierte el bloque binario de subkeys en un diccionario.
    Formato: kname||size(2 bytes)||keydata || kname2||size2||keydata2 ...
    """
    subkeys = {}
    i = 0
    while i < len(blob):
        # Buscar el delimitador '||'
        delim_index = blob.find(b"||", i)
        if delim_index == -1:
            break  # No más claves

        kname = blob[i:delim_index].decode()
        i = delim_index + 2  # Avanzar después de "||"

        # Extraer tamaño (2 bytes)
        size = int.from_bytes(blob[i:i+2], 'big')
        i += 2  # Avanzar después del tamaño

        # Extraer clave
        keydata = blob[i:i+size]
        i += size + 2  # Avanzar después de keydata y "||"

        subkeys[kname] = keydata

    return subkeys

# Cifrado y descifrado según el modo y la técnica

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data))

def ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(data)
    return pkcs7_unpad(dec)

def technique_encrypt(plaintext, subkeys, technique):
    if technique == "none":
        return ecb_encrypt(plaintext, subkeys["k1"])
    elif technique == "double":
        tmp = ecb_encrypt(plaintext, subkeys["k1"])
        return ecb_encrypt(tmp, subkeys["k2"])
    elif technique == "triple":
        tmp1 = ecb_encrypt(plaintext, subkeys["k1"])
        tmp2 = ecb_encrypt(tmp1, subkeys["k2"])
        return ecb_encrypt(tmp2, subkeys["k3"])
    elif technique == "whitening":
        block = xor_bytes(plaintext, subkeys["w1"])
        enc_block = ecb_encrypt(block, subkeys["k2"])
        return xor_bytes(enc_block, subkeys["w3"])
    else:
        raise ValueError("Técnica desconocida")

def technique_decrypt(ciphertext, subkeys, technique):
    if technique == "none":
        return ecb_decrypt(ciphertext, subkeys["k1"])
    elif technique == "double":
        tmp = ecb_decrypt(ciphertext, subkeys["k2"])
        return ecb_decrypt(tmp, subkeys["k1"])
    elif technique == "triple":
        tmp1 = ecb_decrypt(ciphertext, subkeys["k3"])
        tmp2 = ecb_decrypt(tmp1, subkeys["k2"])
        return ecb_decrypt(tmp2, subkeys["k1"])
    elif technique == "whitening":
        block_enc = xor_bytes(ciphertext, subkeys["w3"])
        dec_block_padded = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(block_enc)
        dec_block = pkcs7_unpad(dec_block_padded)
        return xor_bytes(dec_block, subkeys["w1"])
    else:
        raise ValueError("Técnica desconocida")

def mode_encrypt(plaintext, mode, subkeys, technique):
    # Primero aplica la técnica
    tech_out = technique_encrypt(plaintext, subkeys, technique)
    if mode == "ECB":
        return tech_out
    elif mode == "CBC":
        iv = os.urandom(16)
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pkcs7_pad(tech_out))
    elif mode == "CTR":
        nonce = os.urandom(8)
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        return nonce + cipher.encrypt(tech_out)
    else:
        raise ValueError("Modo no soportado")

def mode_decrypt(ciphertext, mode, subkeys, technique):
    if mode == "ECB":
        return technique_decrypt(ciphertext, subkeys, technique)
    elif mode == "CBC":
        iv = ciphertext[:16]
        cbc_data = ciphertext[16:]
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        dec_tech_padded = cipher.decrypt(cbc_data)
        dec_tech = pkcs7_unpad(dec_tech_padded)
        return technique_decrypt(dec_tech, subkeys, technique)
    elif mode == "CTR":
        nonce = ciphertext[:8]
        ctr_data = ciphertext[8:]
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        dec_tech = cipher.decrypt(ctr_data)
        return technique_decrypt(dec_tech, subkeys, technique)
    else:
        raise ValueError("Modo no soportado")

# CLIENTE
def main():
    if len(sys.argv) < 4:
        print("Uso: python client.py <MODE> <TECHNIQUE> <KEY_FILE>")
        print("  <MODE>: ECB, CBC, CTR")
        print("  <TECHNIQUE>: none, double, triple, whitening")
        print("  <KEY_FILE>: Ruta del archivo que contiene la MAIN_KEY")
        return

    mode = sys.argv[1]
    technique = sys.argv[2]
    key_file = sys.argv[3]  # Ruta del archivo de la clave

    # Cargar MAIN_KEY desde el archivo
    MAIN_KEY = load_main_key(key_file)
    if not MAIN_KEY:
        print("[CLIENTE] Error: No se pudo cargar la MAIN_KEY.")
        return

    print(f"[CLIENTE] Modo: {mode}, Técnica: {technique}, MAIN_KEY cargada correctamente.")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"[CLIENTE] Conectado a {HOST}:{PORT}")

    # (3) Enviar modo y técnica en claro
    send_message(client_socket, mode.encode())
    send_message(client_socket, technique.encode())

    # (4) Recibir sub-llaves cifradas (AES CBC con MAIN_KEY)
    enc_subkeys = recv_message(client_socket)
    if not enc_subkeys:
        print("[CLIENTE] No llegó subkeys. Saliendo.")
        client_socket.close()
        return

    # Descifrar subllaves con la MAIN_KEY
    subkeys_blob = aes_cbc_decrypt(enc_subkeys, MAIN_KEY)
    # Parsear subkeys
    subkeys = parse_subkeys(subkeys_blob)
    print("[CLIENTE] Subkeys recibidas:", {k: v.hex() for k, v in subkeys.items()})

    # (5) Toda la comunicación posterior con la combinación (mode + technique)
    while True:
        msg = input("[CLIENTE] Escribe mensaje (o 'exit'): ")
        if msg.lower() == "exit":
            # Enviamos mensaje vacío para indicar cierre
            send_message(client_socket, b'')
            break

        # Cifrar
        ciphertext = mode_encrypt(msg.encode(), mode, subkeys, technique)
        send_message(client_socket, ciphertext)

        # Recibir respuesta
        enc_resp = recv_message(client_socket)
        if not enc_resp:
            print("[CLIENTE] Servidor cerró conexión.")
            break

        dec_resp = mode_decrypt(enc_resp, mode, subkeys, technique)
        try:
            print("[CLIENTE] Respuesta:", dec_resp.decode())
        except:
            print("[CLIENTE] Respuesta (binario):", dec_resp)

    client_socket.close()
    print("[CLIENTE] Finalizado.")

if __name__ == "__main__":
    main()