# **Parcial 1 de Criptografía: Comunicación Segura con AES, Salsa20 y ChaCha20**

Este proyecto implementa un sistema de comunicación segura entre un cliente y un servidor utilizando algoritmos de cifrado simétrico como **AES (Advanced Encryption Standard)**, **Salsa20** y **ChaCha20**. El sistema permite elegir entre diferentes modos de operación (ECB, CBC, CTR) para AES, así como entre Salsa20 y ChaCha20 para cifradores de flujo.

---

## **Tabla de Contenidos**
1. [Descripción del Proyecto](#descripción-del-proyecto)
2. [Características](#características)
3. [Requisitos](#requisitos)
4. [Instalación](#instalación)
5. [Uso](#uso)
6. [Pruebas](#pruebas)


---

## **Descripción del Proyecto**

Este proyecto demuestra cómo implementar un sistema de comunicación segura utilizando cifrado simétrico con **AES**, **Salsa20** y **ChaCha20**. El servidor y el cliente intercambian mensajes cifrados, y el usuario puede elegir entre diferentes algoritmos y modos de operación para mejorar la confidencialidad e integridad de los datos.

El proyecto está diseñado con fines educativos y puede ser utilizado como base para implementar sistemas de comunicación segura en entornos reales.

---

## **Características**

- **Algoritmos de Cifrado**:
  - **AES** (Advanced Encryption Standard):
    - Modos de operación: ECB, CBC, CTR.
    - Técnicas de seguridad adicional: ninguna, cifrado doble, cifrado triple, blanqueamiento de llave.
  - **Salsa20**: Cifrador de flujo rápido y seguro.
  - **ChaCha20**: Cifrador de flujo moderno y eficiente.

- **Gestión de Llaves**:
  - Uso de una llave simétrica de 256 bits compartida previamente.
  - Generación y envío seguro de nonces (números usados una vez).

- **Comunicación**:
  - Protocolo personalizado para enviar y recibir mensajes cifrados.
  - Soporte para mensajes de longitud variable.

---

## **Requisitos**

- **Python 3.8 o superior**.
- **Bibliotecas de Python**:
  - `pycryptodome` (para cifrado AES, Salsa20 y ChaCha20).
  - Instálala con:
    ```bash
    pip install pycryptodome
    ```

---

## Instalación

Instala las dependencias:

bash
Copy
pip install -r requirements.txt

## Uso
### 1. Ejecutar el Servidor

Dependiendo del algoritmo de cifrado que quieras usar, ejecuta el servidor correspondiente:

- **AES**  
```bash
python Aes/server.py
```

- **Salsa20 o ChaCha20**  
```bash
python Salsa20-ChaCha20/server.py
```

### 2. Ejecutar el Cliente

Para conectarse al servidor y enviar mensajes cifrados, ejecuta el cliente correspondiente según el algoritmo:

- **AES**  
```bash
python Aes/client.py
```

- **Salsa20 o ChaCha20**  
```bash
python Salsa20-ChaCha20/client.py
```

Si usas AES, primero genera una clave con:

```bash
python Aes/keygen.py
```

Esto creará el archivo `main_key.bin` en la carpeta `Aes`.

### 3. Enviar Mensajes

Una vez conectado, el cliente permite enviar mensajes al servidor.  
Escribe `exit` para cerrar la conexión.

## Pruebas

El proyecto incluye un archivo de pruebas (test.py) para verificar el funcionamiento del cifrado y descifrado.

### Ejecutar Pruebas

bash
Copy
python test.py

### Pruebas Incluidas

Cifrado y descifrado con AES en modo ECB, CBC y CTR.

Cifrado y descifrado con Salsa20.

Cifrado y descifrado con ChaCha20.
