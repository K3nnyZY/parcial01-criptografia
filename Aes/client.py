import socket
import sys
import os
from Crypto.Cipher import AES

###############################################################################
# Se asume que el Cliente conoce la MAIN_KEY por un canal alterno.
###############################################################################
MAIN_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
           b'\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10' \
           b'\x11\x12\x13\x14\x15\x16\x17\x18' \
           b'\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20'

HOST = '127.0.0.1'
PORT = 6000

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

###############################################################################
# Parsear las subkeys recibidas en binario
###############################################################################
def parse_subkeys(blob):
    """
    Formato: kname||size(2 bytes)||kval || kname2||size2||kval2 ...
    """
    parts = blob.split(b"||")
    # Ejemplo: [b'k1', b'\x00 ', b'k2', b'\x00 ', b''] ...
    subkeys = {}
    i = 0
    while i < len(parts) - 1:  # El último suele ser b''
        kname = parts[i].decode()
        size_bytes = parts[i+1][:2]
        ksize = int.from_bytes(size_bytes, 'big')
        keydata = parts[i+1][2:2+ksize]
        subkeys[kname] = keydata
        i += 2
    return subkeys

###############################################################################
# CIFRADO POSTERIOR: Modo + Técnica
###############################################################################
from Crypto.Cipher import AES

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

###############################################################################
# CLIENTE
###############################################################################
def main():
    if len(sys.argv) < 3:
        print("Uso: python client.py <MODE> <TECHNIQUE>")
        print("  <MODE>: ECB, CBC, CTR")
        print("  <TECHNIQUE>: none, double, triple, whitening")
        return

    mode = sys.argv[1]
    technique = sys.argv[2]

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
