import socket
import sys
import os
from Crypto.Cipher import Salsa20, ChaCha20

HOST = '127.0.0.1'
PORT = 5000

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

def main():
    # Por defecto, "Salsa20", a menos que recibamos "ChaCha20" como argumento
    cipher_name = "Salsa20"
    if len(sys.argv) > 1:
        cipher_name = sys.argv[1]

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"Conectado al servidor {HOST}:{PORT}")

    # 1. Enviar el nombre del cifrador
    send_message(client_socket, cipher_name.encode())

    # 2. Recibir la llave del servidor
    key_data = recv_message(client_socket)
    if not key_data:
        print("No se recibió la llave. Saliendo...")
        client_socket.close()
        return

    key = key_data
    print(f"Cliente recibió la llave de 256 bits: {key.hex()}")

    # Determinar tamaño del nonce según el cifrador
    if cipher_name == "Salsa20":
        nonce_size = 8
    else:
        nonce_size = 12

    # 3. Bucle para enviar mensajes al servidor
    while True:
        user_input = input("Mensaje para enviar (o 'exit' para salir): ")
        if user_input.lower() == 'exit':
            # Enviamos un mensaje vacío para indicar fin (o puedes simplemente cerrar)
            send_message(client_socket, b'')
            break

        # Generar nonce único para este mensaje
        nonce_client = os.urandom(nonce_size)

        if cipher_name == "Salsa20":
            cipher = Salsa20.new(key=key, nonce=nonce_client)
        else:
            cipher = ChaCha20.new(key=key, nonce=nonce_client)

        ciphertext_client = cipher.encrypt(user_input.encode())

        # Enviar nonce + ciphertext
        send_message(client_socket, nonce_client + ciphertext_client)

        # Recibir la respuesta del servidor
        encrypted_response = recv_message(client_socket)
        if not encrypted_response:
            print("El servidor cerró la conexión o envió un mensaje vacío.")
            break

        # Extraer nonce del servidor y descifrar
        nonce_server = encrypted_response[:nonce_size]
        ciphertext_server = encrypted_response[nonce_size:]

        if cipher_name == "Salsa20":
            cipher = Salsa20.new(key=key, nonce=nonce_server)
        else:
            cipher = ChaCha20.new(key=key, nonce=nonce_server)

        plaintext_server = cipher.decrypt(ciphertext_server)
        print("Respuesta del servidor (descrifrada):", plaintext_server.decode())

    client_socket.close()
    print("Conexión terminada.")

if __name__ == "__main__":
    main()