import socket
import sys
import os
from Crypto.Cipher import AES


# ------------------------- 1. CARGA DE LA LLAVE PRINCIPAL (MAIN_KEY) ------------------------- #
def load_main_key(file_path):
    """
    Carga la MAIN_KEY desde un archivo binario.

    Parámetros:
    - file_path (str): Ruta del archivo donde está guardada la MAIN_KEY.

    Retorna:
    - main_key (bytes): La clave AES-256 cargada.
    - None si el archivo no existe.
    """
    if not os.path.exists(file_path):  # Verifica si el archivo existe
        print(f"[CLIENTE] Archivo {file_path} no encontrado.")
        return None

    with open(file_path, "rb") as f:
        main_key = f.read()  # Lee la clave desde el archivo binario

    print("[CLIENTE] MAIN_KEY cargada:", main_key.hex())  # Muestra la clave en formato hexadecimal
    return main_key  # Retorna la clave cargada

# Configuración de la dirección IP y puerto del servidor
HOST = '127.0.0.1'
PORT = 5000


# ------------------------- 2. MANEJO DE MENSAJES ------------------------- #
def recv_exact(sock, num_bytes):
    """
    Recibe exactamente 'num_bytes' desde el socket.
    Esto es necesario porque las operaciones de socket pueden devolver menos bytes de lo esperado.
    """
    data = b''  # Inicializa un buffer vacío
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))  # Recibe los bytes restantes
        if not chunk:
            return None  # Si no se recibe nada, retorna None
        data += chunk  # Acumula los datos recibidos
    return data  # Retorna los datos completos recibidos

def recv_message(sock):
    """
    Recibe un mensaje completo desde el socket.
    Los primeros 4 bytes indican la longitud del mensaje, seguido de los datos.
    """
    length_data = recv_exact(sock, 4)  # Recibe los primeros 4 bytes con el tamaño del mensaje
    if not length_data:
        return None
    msg_len = int.from_bytes(length_data, 'big')  # Convierte los bytes a un número entero
    if msg_len == 0:
        return b''  # Si el tamaño es 0, retorna un mensaje vacío
    return recv_exact(sock, msg_len)  # Recibe el mensaje completo según el tamaño indicado

def send_message(sock, data):
    """
    Envía un mensaje precedido por su longitud (4 bytes).
    """
    msg_len = len(data)  # Obtiene la longitud del mensaje
    sock.sendall(msg_len.to_bytes(4, 'big'))  # Envía la longitud en 4 bytes
    sock.sendall(data)  # Envía los datos


# ------------------------- 3. UTILIDADES DE CIFRADO AES ------------------------- #
def pkcs7_pad(data, block_size=16):
    """
    Aplica padding PKCS#7 para asegurar que los datos sean múltiplos del tamaño del bloque AES (16 bytes).
    """
    pad_len = block_size - (len(data) % block_size)  # Calcula cuántos bytes de padding se necesitan
    return data + bytes([pad_len]) * pad_len  # Agrega los bytes de padding

def pkcs7_unpad(data):
    """
    Elimina el padding PKCS#7 después de descifrar.
    """
    pad_len = data[-1]  # Obtiene el número de bytes de padding
    return data[:-pad_len]  # Retorna los datos originales sin padding

def aes_cbc_decrypt(data, key):
    """
    Descifra datos usando AES en modo CBC.
    El IV se extrae de los primeros 16 bytes del mensaje.
    """
    iv = data[:16]  # Extrae el IV de los primeros 16 bytes
    ciphertext = data[16:]  # Obtiene el texto cifrado sin el IV
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Configura el descifrador AES en modo CBC
    dec_padded = cipher.decrypt(ciphertext)  # Descifra los datos
    return pkcs7_unpad(dec_padded)  # Retorna los datos originales sin padding


# ------------------------- 4. PARSEO DE SUB-LLAVES ------------------------- #
def parse_subkeys(blob):
    """
    Convierte el bloque binario de subkeys en un diccionario.
    Formato esperado: kname||size(2 bytes)||keydata || kname2||size2||keydata2 ...
    """
    subkeys = {}  # Diccionario para almacenar las claves
    i = 0
    while i < len(blob):
        delim_index = blob.find(b"||", i)  # Encuentra el delimitador "||"
        if delim_index == -1:
            break  # No más claves

        kname = blob[i:delim_index].decode()  # Extrae el nombre de la clave
        i = delim_index + 2  # Avanza después de "||"

        size = int.from_bytes(blob[i:i+2], 'big')  # Extrae el tamaño (2 bytes)
        i += 2  # Avanza después del tamaño

        keydata = blob[i:i+size]  # Extrae la clave
        i += size + 2  # Avanza después de keydata y "||"

        subkeys[kname] = keydata  # Guarda la clave en el diccionario

    return subkeys  # Retorna el diccionario con las subclaves


# ------------------------- 5. FUNCIONES DE CIFRADO Y DESCIFRADO ------------------------- #
def xor_bytes(a, b):
    """Realiza una operación XOR entre dos bytes."""
    return bytes(x ^ y for x, y in zip(a, b))

def ecb_encrypt(data, key):
    """Cifra usando AES en modo ECB."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data))

def ecb_decrypt(data, key):
    """Descifra usando AES en modo ECB."""
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(data)
    return pkcs7_unpad(dec)


# ------------------------- 6. APLICACIÓN DE TÉCNICAS DE CIFRADO ------------------------- #
def technique_encrypt(plaintext, subkeys, technique):
    """
    Aplica la técnica de cifrado antes del modo de cifrado.

    Parámetros:
    - plaintext (bytes): Datos en claro que se van a cifrar.
    - subkeys (dict): Diccionario con las sub-llaves necesarias para la técnica.
    - technique (str): Técnica de cifrado seleccionada ("none", "double", "triple", "whitening").

    Retorna:
    - (bytes) Datos cifrados según la técnica aplicada.
    """
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
    """
    Aplica la técnica de descifrado antes del modo de descifrado.

    Parámetros:
    - ciphertext (bytes): Datos cifrados que se van a descifrar.
    - subkeys (dict): Diccionario con las sub-llaves necesarias para la técnica.
    - technique (str): Técnica de cifrado utilizada.

    Retorna:
    - (bytes) Datos descifrados después de aplicar la técnica.
    """
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


# ------------------------- 7. APLICACIÓN DEL MODO DE CIFRADO ------------------------- #
def mode_encrypt(plaintext, mode, subkeys, technique):
    """
    Aplica la técnica de cifrado y luego el modo de cifrado seleccionado.

    Parámetros:
    - plaintext (bytes): Datos en claro.
    - mode (str): Modo de cifrado seleccionado ("ECB", "CBC", "CTR").
    - subkeys (dict): Diccionario con las sub-llaves generadas.
    - technique (str): Técnica de cifrado seleccionada.

    Retorna:
    - (bytes) Datos cifrados con la técnica + modo de cifrado.
    """
    tech_out = technique_encrypt(plaintext, subkeys, technique)  # Aplica la técnica

    if mode == "ECB":
        return tech_out
    elif mode == "CBC":
        iv = os.urandom(16)  # Genera IV aleatorio
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pkcs7_pad(tech_out))
    elif mode == "CTR":
        nonce = os.urandom(8)  # Genera nonce aleatorio
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        return nonce + cipher.encrypt(tech_out)
    else:
        raise ValueError("Modo no soportado")

def mode_decrypt(ciphertext, mode, subkeys, technique):
    """
    Aplica el modo de descifrado y luego la técnica de descifrado.

    Parámetros:
    - ciphertext (bytes): Datos cifrados.
    - mode (str): Modo de cifrado usado.
    - subkeys (dict): Diccionario con las sub-llaves.
    - technique (str): Técnica de cifrado utilizada.

    Retorna:
    - (bytes) Datos descifrados.
    """
    if mode == "ECB":
        return technique_decrypt(ciphertext, subkeys, technique)
    elif mode == "CBC":
        iv = ciphertext[:16]  # Extrae el IV
        cbc_data = ciphertext[16:]  # Obtiene el resto de los datos cifrados
        cipher = AES.new(subkeys["k1"], AES.MODE_CBC, iv)
        dec_tech_padded = cipher.decrypt(cbc_data)
        dec_tech = pkcs7_unpad(dec_tech_padded)
        return technique_decrypt(dec_tech, subkeys, technique)
    elif mode == "CTR":
        nonce = ciphertext[:8]  # Extrae el nonce
        ctr_data = ciphertext[8:]  # Obtiene los datos cifrados restantes
        cipher = AES.new(subkeys["k1"], AES.MODE_CTR, nonce=nonce)
        dec_tech = cipher.decrypt(ctr_data)
        return technique_decrypt(dec_tech, subkeys, technique)
    else:
        raise ValueError("Modo no soportado")
    

# ------------------------- 8. CLIENTE ------------------------- #
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