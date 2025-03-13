import socket
import sys
from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 6000

# Se asume que el cliente también conoce MAIN_KEY (offline).
MAIN_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
           b'\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10' \
           b'\x11\x12\x13\x14\x15\x16\x17\x18' \
           b'\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20'

###############################################################################
# Helper para mensajes (igual que en server)
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
# Mismo cifrado y utilidades (copiadas del server)
###############################################################################
def aes_cbc_decrypt(iv_ciphertext, key):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = cipher.decrypt(ciphertext)
    pad_len = data_padded[-1]
    return data_padded[:-pad_len]

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data, block_size=16):
    pad_len = data[-1]
    return data[:-pad_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

###############################################################################
# Mismo apply_technique, block_mode, generate_subkeys, etc. no se repite aquí
# => IMPORTANTE: Para la demo, simplemente replicamos la parte que necesitamos
#    en el CLIENTE para cifrar/descifrar mensajes POSTERIORES al handshake.
#    (Podríamos mover todo a un "common.py" si quisiéramos.)
###############################################################################

def apply_technique_encrypt(plaintext, subkeys, technique):
    from Crypto.Cipher import AES
    def pkcs7_pad(d, bs=16):
        pl = bs - (len(d) % bs)
        return d + bytes([pl])*pl

    if technique == "none":
        return AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
    elif technique == "double":
        tmp = AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
        return AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(tmp)
    elif technique == "triple":
        tmp1 = AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
        tmp2 = AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(tmp1)
        return AES.new(subkeys["k3"], AES.MODE_ECB).encrypt(tmp2)
    elif technique == "whitening":
        block = xor_bytes(plaintext, subkeys["w1"])
        block_enc = AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(pkcs7_pad(block))
        final = xor_bytes(block_enc, subkeys["w3"])
        return final
    else:
        raise ValueError("Técnica desconocida")

def apply_technique_decrypt(ciphertext, subkeys, technique):
    from Crypto.Cipher import AES
    def pkcs7_unpad(d, bs=16):
        pl = d[-1]
        return d[:-pl]

    if technique == "none":
        tmp = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(ciphertext)
        return pkcs7_unpad(tmp)
    elif technique == "double":
        tmp = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(ciphertext)
        tmp2 = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(tmp)
        return pkcs7_unpad(tmp2)
    elif technique == "triple":
        tmp1 = AES.new(subkeys["k3"], AES.MODE_ECB).decrypt(ciphertext)
        tmp2 = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(tmp1)
        tmp3 = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(tmp2)
        return pkcs7_unpad(tmp3)
    elif technique == "whitening":
        block_enc = xor_bytes(ciphertext, subkeys["w3"])
        block_dec_padded = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(block_enc)
        block_dec = pkcs7_unpad(block_dec_padded)
        return xor_bytes(block_dec, subkeys["w1"])
    else:
        raise ValueError("Técnica desconocida")


def block_mode_encrypt(plaintext, mode, subkeys, technique):
    from Crypto.Cipher import AES
    if mode == "ECB":
        return apply_technique_encrypt(plaintext, subkeys, technique)
    elif mode == "CBC":
        iv = os.urandom(16)
        block_tech = apply_technique_encrypt(plaintext, subkeys, technique)
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        cbc_out = cipher.encrypt(pkcs7_pad(block_tech))
        return iv + cbc_out
    elif mode == "CTR":
        nonce = os.urandom(8)
        block_tech = apply_technique_encrypt(plaintext, subkeys, technique)
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        ctr_out = cipher.encrypt(block_tech)
        return nonce + ctr_out
    else:
        raise ValueError("Modo no soportado")

def block_mode_decrypt(ciphertext, mode, subkeys, technique):
    from Crypto.Cipher import AES
    if mode == "ECB":
        return apply_technique_decrypt(ciphertext, subkeys, technique)
    elif mode == "CBC":
        iv = ciphertext[:16]
        cbc_out = ciphertext[16:]
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        block_tech_padded = cipher.decrypt(cbc_out)
        block_tech = pkcs7_unpad(block_tech_padded)
        return apply_technique_decrypt(block_tech, subkeys, technique)
    elif mode == "CTR":
        nonce = ciphertext[:8]
        ctr_out = ciphertext[8:]
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        block_tech = cipher.decrypt(ctr_out)
        return apply_technique_decrypt(block_tech, subkeys, technique)
    else:
        raise ValueError("Modo no soportado")

###############################################################################
# CLIENT
###############################################################################

def main():
    if len(sys.argv) < 3:
        print(f"Uso: python client.py <MODE> <TECHNIQUE>")
        print("MODE: ECB, CBC, CTR")
        print("TECHNIQUE: none, double, triple, whitening")
        sys.exit(1)

    mode = sys.argv[1]
    technique = sys.argv[2]

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"[CLIENTE] Conectado a {HOST}:{PORT}")

    # 1. Enviar modo y técnica al servidor
    send_message(client_socket, mode.encode())
    send_message(client_socket, technique.encode())

    # 2. Recibir las subllaves (cifradas con AES-CBC y MAIN_KEY)
    enc_subkeys = recv_message(client_socket)
    if not enc_subkeys:
        print("[CLIENTE] No llegaron subllaves. Saliendo.")
        client_socket.close()
        return

    # 3. Descifrar subllaves
    from Crypto.Cipher import AES
    def aes_cbc_decrypt(iv_ciphertext, key):
        iv = iv_ciphertext[:16]
        ciphertext = iv_ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data_padded = cipher.decrypt(ciphertext)
        pad_len = data_padded[-1]
        return data_padded[:-pad_len]

    subkeys_blob = aes_cbc_decrypt(enc_subkeys, MAIN_KEY)

    # 4. Parsear subkeys
    # subkeys_blob = kname||size||kval || kname2||size2||kval2 ...
    # terminamos cada "campo" con "||" => haremos un split
    parts = subkeys_blob.split(b"||")
    # Ejemplo: [b'k1', b'\x00\x20<KEY>', b'k2', b'\x00\x20<KEY>', b'']
    # Lo parseamos en pares: (kname, size, keydata)
    subkeys = {}
    i = 0
    while i < len(parts) - 1:  # último elemento es '' por el split final
        kname = parts[i].decode()
        size_bytes = parts[i+1][:2]
        kval_size = int.from_bytes(size_bytes, 'big')
        kval = parts[i+1][2:2+kval_size]
        subkeys[kname] = kval
        i += 2

    print("[CLIENTE] Subllaves recibidas:", {k: v.hex() for k, v in subkeys.items()})

    # 5. Intercambio de mensajes POSTERIORES
    while True:
        msg = input("[CLIENTE] Escribe un mensaje (o 'exit'): ")
        if msg.lower() == "exit":
            send_message(client_socket, b'')
            break

        # Cifrar con la combinación (mode, technique, subkeys)
        ciphertext = block_mode_encrypt(msg.encode(), mode, subkeys, technique)

        # Enviarlo
        send_message(client_socket, ciphertext)

        # Recibir respuesta
        encrypted_resp = recv_message(client_socket)
        if not encrypted_resp:
            print("[CLIENTE] Servidor cerró la conexión.")
            break

        resp_plain = block_mode_decrypt(encrypted_resp, mode, subkeys, technique)
        try:
            print("[CLIENTE] Respuesta:", resp_plain.decode())
        except:
            print("[CLIENTE] Respuesta (binario):", resp_plain)

    client_socket.close()
    print("[CLIENTE] Conexión finalizada.")

if __name__ == "__main__":
    main()
