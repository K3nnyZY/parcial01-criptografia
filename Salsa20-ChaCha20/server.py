import socket
import os
from Crypto.Cipher import Salsa20, ChaCha20

HOST = '127.0.0.1'
PORT = 5000

def recv_exact(sock, num_bytes):
    # Asegura que se reciban exactamente num_bytes del socket.
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_message(sock):
   #Recibe un mensaje del socket, Primero lee 4 bytes para determinar la longitud del mensaje.
    length_data = recv_exact(sock, 4)
    if not length_data:
        return None
    msg_len = int.from_bytes(length_data, 'big')
    if msg_len == 0:
        return b''
    return recv_exact(sock, msg_len)

def send_message(sock, data):
    # Enviar un mensaje al socket, Primeros 4 bytes indican la longitud del mensaje
    msg_len = len(data)
    sock.sendall(msg_len.to_bytes(4, 'big'))
    sock.sendall(data)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Servidor escuchando en {HOST}:{PORT}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Cliente conectado desde {addr}")

        # 1. Recibir el cifrador elegido por el Cliente (Salsa20 o ChaCha20)
        cipher_name_data = recv_message(conn)
        if not cipher_name_data:
            print("No se recibió nombre de cifrador. Cerrando conexión.")
            conn.close()
            continue
        cipher_name = cipher_name_data.decode().strip()
        print(f"El cliente solicita usar: {cipher_name}")

        # 2. Generar una llave de 256 bits y enviarla en claro
        key = os.urandom(32)  # 256 bits
        print(f"Servidor generó la llave de 256 bits: {key.hex()}")

        # Enviamos la llave con nuestro protocolo de longitud + datos
        send_message(conn, key)

        # Determinar tamaño de nonce según cifrador
        if cipher_name == "Salsa20":
            nonce_size = 8
        else:
            # ChaCha20 comúnmente usa 12 bytes de nonce
            nonce_size = 12

        # 3. Bucle para intercambio de mensajes (cifrados)
        while True:
            # Recibir mensaje del cliente (nonce + ciphertext)
            encrypted_msg = recv_message(conn)
            if encrypted_msg is None:
                print("El cliente cerró la conexión.")
                break
            if len(encrypted_msg) == 0:
                # Si mensaje == b'' => no hay nada más
                print("Mensaje vacío: fin de la comunicación.")
                break

            # El primer tramo del mensaje es el nonce
            nonce_client = encrypted_msg[:nonce_size]
            print(f"Nonce recibido: {nonce_client.hex()}")

            # El resto del mensaje es el ciphertext
            ciphertext_client = encrypted_msg[nonce_size:]

            # Descifrar el texto recibido
            if cipher_name == "Salsa20":
                cipher = Salsa20.new(key=key, nonce=nonce_client)
            else:
                cipher = ChaCha20.new(key=key, nonce=nonce_client)

            plaintext_client = cipher.decrypt(ciphertext_client)
            msg_decoded = plaintext_client.decode()
            print(f"Cliente dice: {msg_decoded}")

            response_plain = f"Eco del servidor: {msg_decoded}"

            # Generar un nonce nuevo para nuestra respuesta
            nonce_server = os.urandom(nonce_size)
            if cipher_name == "Salsa20":
                cipher = Salsa20.new(key=key, nonce=nonce_server)
            else:
                cipher = ChaCha20.new(key=key, nonce=nonce_server)
            
            encrypted_response = cipher.encrypt(response_plain.encode())

            # Enviar (nonce + ciphertext)
            send_message(conn, nonce_server + encrypted_response)

        conn.close()
        print("Conexión cerrada.\n")

if __name__ == "__main__":
    main()