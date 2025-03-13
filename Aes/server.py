import socket
import os
from Crypto.Cipher import AES

###############################################################################
# 1) LLAVE PRINCIPAL DE 256 BITS (AES-256)
#    Se asume compartida con el Cliente por un canal alterno (USB, email, etc.)
###############################################################################
MAIN_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
           b'\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10' \
           b'\x11\x12\x13\x14\x15\x16\x17\x18' \
           b'\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20'  # 32 bytes, 256 bits

HOST = '127.0.0.1'
PORT = 6000

###############################################################################
# 2) MANEJO DE MENSAJES: Envío y recepción (longitud + datos)
###############################################################################
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

###############################################################################
# 3) UTILIDADES DE CIFRADO: AES CBC (para proteger las sub-llaves)
###############################################################################
def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_cbc_encrypt(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pkcs7_pad(data))
    return iv + ciphertext  # Guardamos IV al inicio

def aes_cbc_decrypt(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(dec_padded)

###############################################################################
# 4) GENERAR SUB-LLAVES PARA LA TÉCNICA (none, double, triple, whitening)
###############################################################################
def generate_subkeys(technique):
    """
    Retorna un diccionario con las llaves/valores necesarios:
      - none -> {'k1': 32 bytes}
      - double -> {'k1': 32 bytes, 'k2': 32 bytes}
      - triple -> {'k1': 32 bytes, 'k2': 32 bytes, 'k3': 32 bytes}
      - whitening -> {'w1': 16 bytes, 'k2': 32 bytes, 'w3': 16 bytes}
    """
    if technique == "none":
        return {"k1": os.urandom(32)}
    elif technique == "double":
        return {"k1": os.urandom(32), "k2": os.urandom(32)}
    elif technique == "triple":
        return {"k1": os.urandom(32), "k2": os.urandom(32), "k3": os.urandom(32)}
    elif technique == "whitening":
        # Ejemplo simple: w1 y w3 de 16 bytes, k2 de 32 bytes
        return {"w1": os.urandom(16), "k2": os.urandom(32), "w3": os.urandom(16)}
    else:
        raise ValueError("Técnica desconocida")

def pack_subkeys(subkeys):
    """
    Convierte el diccionario de subkeys en un bloque binario que el Cliente podrá
    parsear. Formato: kname||size(2bytes)||keyData || kname2||size2||keyData2 ...
    Terminamos con || al final.
    """
    blob = b''
    for kname, kval in subkeys.items():
        size_bytes = len(kval).to_bytes(2, 'big')
        blob += kname.encode() + b"||" + size_bytes + kval + b"||"
    return blob

###############################################################################
# 5) CIFRADO DE MENSAJES POSTERIORES: MODO (ECB, CBC, CTR) + TÉCNICA
#    En una implementación "real", lo harías bloque a bloque, pero aquí
#    haremos una demo "envolviendo" el mensaje completo para simplificar.
###############################################################################
from Crypto.Cipher import AES

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def technique_encrypt(plaintext, subkeys, technique):
    """
    Aplica 'none', 'double', 'triple', 'whitening' a un plaintext.
    Usamos AES-256 en ECB internamente (salvo la whitening).
    """
    def ecb_encrypt(data, key):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pkcs7_pad(data))

    if technique == "none":
        # AES_k1(plaintext)
        return ecb_encrypt(plaintext, subkeys["k1"])
    elif technique == "double":
        # AES_k2(AES_k1(plaintext))
        tmp = ecb_encrypt(plaintext, subkeys["k1"])
        return ecb_encrypt(tmp, subkeys["k2"])
    elif technique == "triple":
        # AES_k3(AES_k2(AES_k1(plaintext)))
        tmp1 = ecb_encrypt(plaintext, subkeys["k1"])
        tmp2 = ecb_encrypt(tmp1, subkeys["k2"])
        return ecb_encrypt(tmp2, subkeys["k3"])
    elif technique == "whitening":
        # Ejemplo: ciphertext = [AES_k2( (plaintext XOR w1) )] XOR w3
        block = xor_bytes(plaintext, subkeys["w1"])
        enc_block = ecb_encrypt(block, subkeys["k2"])  # -> ciphertext padded
        return xor_bytes(enc_block, subkeys["w3"])
    else:
        raise ValueError("Técnica desconocida")

def technique_decrypt(ciphertext, subkeys, technique):
    def ecb_decrypt(data, key):
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(data)
        return pkcs7_unpad(dec)

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
        # Inversa de ciphertext = XOR(AES_k2(plaintext XOR w1), w3)
        block_enc = xor_bytes(ciphertext, subkeys["w3"])
        # block_enc es AES_k2(plaintext XOR w1) (padded)
        # -> descifrar y unpad, XOR con w1
        cipher = AES.new(subkeys["k2"], AES.MODE_ECB)
        dec_padded = cipher.decrypt(block_enc)
        dec_block = pkcs7_unpad(dec_padded)
        return xor_bytes(dec_block, subkeys["w1"])
    else:
        raise ValueError("Técnica desconocida")

def mode_encrypt(plaintext, mode, subkeys, technique):
    """
    Aplica la técnica y luego la envuelve en MODO (ECB, CBC, CTR) con subkeys["k1"].
    Para CBC y CTR, generamos IV/nonce y lo anteponemos al ciphertext.
    """
    # Aplica la técnica "none/double/triple/whitening"
    tech_out = technique_encrypt(plaintext, subkeys, technique)

    if mode == "ECB":
        # Simplemente devolvemos tech_out (ya está "ECB" en la técnica)
        return tech_out
    elif mode == "CBC":
        iv = os.urandom(16)
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        cbc_out = cipher.encrypt(pkcs7_pad(tech_out))
        return iv + cbc_out
    elif mode == "CTR":
        nonce = os.urandom(8)
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        ctr_out = cipher.encrypt(tech_out)
        return nonce + ctr_out
    else:
        raise ValueError("Modo no soportado")

def mode_decrypt(ciphertext, mode, subkeys, technique):
    if mode == "ECB":
        # Directa
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
# SERVIDOR
###############################################################################
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[SERVIDOR] Esperando conexiones en {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVIDOR] Conexión desde {addr}")

        # (3) El Cliente envía "modo" en claro
        mode_data = recv_message(conn)
        if not mode_data:
            conn.close()
            continue
        mode = mode_data.decode().strip()

        # El Cliente envía "técnica" en claro
        technique_data = recv_message(conn)
        if not technique_data:
            conn.close()
            continue
        technique = technique_data.decode().strip()

        print(f"[SERVIDOR] Cliente pide modo {mode}, técnica {technique}")

        # (4) El Servidor genera sub-llaves y las envía cifradas (AES CBC con MAIN_KEY)
        subkeys = generate_subkeys(technique)
        subkeys_blob = pack_subkeys(subkeys)

        enc_subkeys = aes_cbc_encrypt(subkeys_blob, MAIN_KEY)
        send_message(conn, enc_subkeys)

        # (5) Toda la comunicación posterior se cifra con "modo + técnica"
        while True:
            encrypted_msg = recv_message(conn)
            if encrypted_msg is None or len(encrypted_msg) == 0:
                print("[SERVIDOR] El cliente cerró la conexión.")
                break

            # Descifrar el mensaje
            dec_plain = mode_decrypt(encrypted_msg, mode, subkeys, technique)
            try:
                dec_str = dec_plain.decode()
            except:
                dec_str = repr(dec_plain)

            print(f"[SERVIDOR] Mensaje descifrado: {dec_str}")

            # Responder con un Eco
            response = f"Eco del servidor: {dec_str}".encode()
            enc_response = mode_encrypt(response, mode, subkeys, technique)
            send_message(conn, enc_response)

        conn.close()

if __name__ == "__main__":
    main()
