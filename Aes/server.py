import socket
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

###############################################################################
# CONFIGURACIÓN
###############################################################################

# Esta llave principal de 256 bits (AES-256) se asume compartida
# de manera "segura" por un canal alterno (USB, email, etc.).
# En un entorno real, NO la incluiríamos directamente en el código:
MAIN_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08' \
           b'\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10' \
           b'\x11\x12\x13\x14\x15\x16\x17\x18' \
           b'\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20'  # 32 bytes (256 bits)

HOST = '127.0.0.1'
PORT = 6000

###############################################################################
# ENVÍO Y RECEPCIÓN DE MENSAJES (Longitud + Datos)
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
    # Primero 4 bytes => longitud
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
# FUNCIONES DE CIFRADO PARA MANDAR LAS SUBLLAVES (AES EN CBC CON MAIN_KEY)
###############################################################################

def aes_cbc_encrypt(data, key):
    """Cifra 'data' con AES en modo CBC y llave 'key'. Retorna iv + ciphertext."""
    iv = get_random_bytes(16)  # 128 bits
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Para simplificar, usaremos un padding muy básico PKCS#7
    pad_len = 16 - (len(data) % 16)
    data_padded = data + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(data_padded)
    return iv + ciphertext

def aes_cbc_decrypt(iv_ciphertext, key):
    """Descifra 'iv + ciphertext' con AES-CBC y 'key'. Retorna los datos sin padding."""
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = cipher.decrypt(ciphertext)
    # Quitar padding PKCS#7
    pad_len = data_padded[-1]
    return data_padded[:-pad_len]

###############################################################################
# FUNCIONES PARA APLICAR LA TÉCNICA DE CIFRADO (NONE, DOUBLE, TRIPLE, WHITENING)
# Aquí trabajamos a nivel de "un bloque grande" (mensaje entero).
# Para un uso real, deberíamos hacerlo por bloques, pero servirá de DEMO.
###############################################################################

def apply_technique_encrypt(plaintext, subkeys, technique):
    """
    Aplica la técnica: none, double, triple, whitening, a un 'plaintext'.
    Retorna 'ciphertext'.
    subkeys es un diccionario con las llaves necesarias, p.e.:
       {
         "k1": <...>,
         "k2": <...>,
         "k3": <...>,
         "w1": <...>,
         "w3": <...>,
       }
    """
    if technique == "none":
        # Un solo cifrado con k1
        return AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
    elif technique == "double":
        # ciphertext = AES_k2( AES_k1(plaintext) )
        tmp = AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
        return AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(tmp)
    elif technique == "triple":
        # ciphertext = AES_k3( AES_k2( AES_k1(plaintext) ) )
        tmp1 = AES.new(subkeys["k1"], AES.MODE_ECB).encrypt(pkcs7_pad(plaintext))
        tmp2 = AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(tmp1)
        return AES.new(subkeys["k3"], AES.MODE_ECB).encrypt(tmp2)
    elif technique == "whitening":
        # Ejemplo simple: ciphertext = (AES_k2( (plaintext XOR w1) padded )) XOR w3
        block = xor_bytes(plaintext, subkeys["w1"])
        block_enc = AES.new(subkeys["k2"], AES.MODE_ECB).encrypt(pkcs7_pad(block))
        final = xor_bytes(block_enc, subkeys["w3"])
        return final
    else:
        raise ValueError("Técnica desconocida")

def apply_technique_decrypt(ciphertext, subkeys, technique):
    """
    Aplica la técnica inversa para descifrar.
    """
    if technique == "none":
        # plaintext = unpad( AES_k1^-1 (ciphertext) )
        tmp = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(ciphertext)
        return pkcs7_unpad(tmp)
    elif technique == "double":
        # plaintext = unpad( AES_k1^-1( AES_k2^-1( ciphertext ) ) )
        tmp = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(ciphertext)
        tmp2 = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(tmp)
        return pkcs7_unpad(tmp2)
    elif technique == "triple":
        # plaintext = unpad( AES_k1^-1( AES_k2^-1( AES_k3^-1( ciphertext ) ) ) )
        tmp1 = AES.new(subkeys["k3"], AES.MODE_ECB).decrypt(ciphertext)
        tmp2 = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(tmp1)
        tmp3 = AES.new(subkeys["k1"], AES.MODE_ECB).decrypt(tmp2)
        return pkcs7_unpad(tmp3)
    elif technique == "whitening":
        # Inversa de: final = XOR( AES_k2( XOR(plaintext, w1) ), w3 )
        # => block_enc = XOR(final, w3)
        # => block = unpad( AES_k2^-1( block_enc ) )
        # => plaintext = XOR(block, w1)
        block_enc = xor_bytes(ciphertext, subkeys["w3"])
        block_dec_padded = AES.new(subkeys["k2"], AES.MODE_ECB).decrypt(block_enc)
        block_dec = pkcs7_unpad(block_dec_padded)
        return xor_bytes(block_dec, subkeys["w1"])
    else:
        raise ValueError("Técnica desconocida")

###############################################################################
# UTILIDADES: XOR, PADDING
###############################################################################

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data, block_size=16):
    pad_len = data[-1]
    return data[:-pad_len]

###############################################################################
# CIFRADO CON MODO DE OPERACIÓN (ECB, CBC, CTR) - DEMO SENCILLO
###############################################################################

def block_mode_encrypt(plaintext, mode, subkeys, technique):
    """
    Cifra 'plaintext' con:
      - Modo 'mode' (ECB, CBC, CTR)
      - Técnica 'technique' (none, double, triple, whitening)
    Para CBC y CTR, generamos IV / nonce cada vez y lo anteponemos.
    """
    if mode == "ECB":
        # Aplicamos la técnica directamente
        return apply_technique_encrypt(plaintext, subkeys, technique)
    elif mode == "CBC":
        # Generamos un IV de 16 bytes, XOR o la técnica se aplica en cada bloque internamente.
        # Para DEMO: (IV + ciphertext_final).
        iv = get_random_bytes(16)
        # “Encapsulamos” la salida de la técnica adentro de AES-CBC con la k1 (p.e.)
        # OJO: real/strict "double/triple encryption en CBC" es más complejo block-by-block.
        # Para la demo, haremos: primero technique, luego AES-CBC con MAIN_KEY = subkeys["k1"]?
        # Pero se pide "toda la comunicación posterior con la técnica y el modo."
        # Simplificaremos a: apply_technique -> RBC con subkeys => Lo ciframos con AES CBC?
        # Este ejemplo, para no enredar, ciframos con la "apply_technique" en modo ECB
        # y luego un "wrap" con CBC usando subkeys["k1"].
        # *VER NOTA*: Esto es una aproximación de DEMO, no el real block-by-block.
        block_tech = apply_technique_encrypt(plaintext, subkeys, technique)
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        cbc_out = cipher.encrypt(pkcs7_pad(block_tech))
        return iv + cbc_out
    elif mode == "CTR":
        # Generamos un nonce/contador
        nonce = get_random_bytes(8)
        # De nuevo, en la práctica, "double encryption en CTR" se hace block-by-block.
        # Haremos un "wrap": apply_technique -> AES CTR con subkeys["k1"].
        block_tech = apply_technique_encrypt(plaintext, subkeys, technique)
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        ctr_out = cipher.encrypt(block_tech)
        return nonce + ctr_out
    else:
        raise ValueError("Modo no soportado")

def block_mode_decrypt(ciphertext, mode, subkeys, technique):
    """
    Descifra 'ciphertext' según el modo (ECB, CBC, CTR) y la técnica.
    Inversa de la función anterior.
    """
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
# GENERAR SUBLLAVES SEGÚN LA TÉCNICA (DOBLE, TRIPLE, WHITENING, ETC.)
###############################################################################

def generate_subkeys(technique):
    """
    Retorna un diccionario con las llaves o valores necesarios:
      none -> {"k1": <random 256 bits>}
      double -> {"k1":..., "k2":...}
      triple -> {"k1":..., "k2":..., "k3":...}
      whitening -> {"w1":..., "k2":..., "w3":...}
    """
    if technique == "none":
        return {"k1": get_random_bytes(32)}
    elif technique == "double":
        return {"k1": get_random_bytes(32),
                "k2": get_random_bytes(32)}
    elif technique == "triple":
        return {"k1": get_random_bytes(32),
                "k2": get_random_bytes(32),
                "k3": get_random_bytes(32)}
    elif technique == "whitening":
        return {
            "w1": get_random_bytes(16),  # usaremos 16 bytes
            "k2": get_random_bytes(32),  # AES-256
            "w3": get_random_bytes(16)
        }
    else:
        raise ValueError("Técnica desconocida")

###############################################################################
# SERVIDOR MAIN
###############################################################################

def main():
    # Iniciar socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[SERVIDOR] Esperando conexiones en {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVIDOR] Cliente conectado desde {addr}")

        # 1. Recibir modo de operación (ECB, CBC, CTR)
        mode_data = recv_message(conn)
        if not mode_data:
            print("[SERVIDOR] No se recibió modo. Cerrando.")
            conn.close()
            continue
        mode = mode_data.decode().strip()

        # 2. Recibir técnica de seguridad (none, double, triple, whitening)
        technique_data = recv_message(conn)
        if not technique_data:
            print("[SERVIDOR] No se recibió técnica. Cerrando.")
            conn.close()
            continue
        technique = technique_data.decode().strip()

        print(f"[SERVIDOR] El cliente solicita modo: {mode}, técnica: {technique}")

        # 3. Generar subllaves (si aplica)
        subkeys = generate_subkeys(technique)
        # Empaquetar subkeys en un blob (podemos hacerlo en binario o JSON)
        # Para DEMO, lo haremos en binario: key_name||size||key_data ...
        subkeys_blob = b''
        for kname, kval in subkeys.items():
            block = kname.encode() + b"||" + len(kval).to_bytes(2, 'big') + kval
            subkeys_blob += block + b"||"

        # 4. Cifrar subkeys con AES-CBC usando MAIN_KEY
        enc_subkeys = aes_cbc_encrypt(subkeys_blob, MAIN_KEY)

        # 5. Enviar subkeys cifradas al Cliente
        send_message(conn, enc_subkeys)

        # Bucle de mensajes POSTERIORES
        # El cliente enviará (plaintext cifrado con "mode"+"technique"), lo desciframos y respondemos.
        print("[SERVIDOR] Esperando mensajes cifrados del cliente (pos-handshake).")

        while True:
            encrypted_msg = recv_message(conn)
            if encrypted_msg is None or len(encrypted_msg) == 0:
                print("[SERVIDOR] El cliente cerró la conexión.")
                break

            # Descifrar
            plaintext = block_mode_decrypt(encrypted_msg, mode, subkeys, technique)
            try:
                msg_decoded = plaintext.decode()
            except:
                msg_decoded = repr(plaintext)
            print(f"[SERVIDOR] Mensaje descifrado del cliente: {msg_decoded}")

            # Responder con un "Eco"
            response_plain = f"Eco del servidor: {msg_decoded}".encode()
            encrypted_response = block_mode_encrypt(response_plain, mode, subkeys, technique)
            send_message(conn, encrypted_response)

        conn.close()

if __name__ == "__main__":
    main()
