import os

KEY_FILE_PATH = "main_key.bin"

def generate_main_key():
    """Genera una nueva MAIN_KEY de 32 bytes aleatorios y la guarda en un archivo."""
    main_key = os.urandom(32)  # Genera una nueva clave aleatoria de 256 bits
    with open(KEY_FILE_PATH, "wb") as f:
        f.write(main_key)
    print(f"[SERVIDOR] MAIN_KEY generada y guardada en {KEY_FILE_PATH}")
    return main_key

def get_key_file_path():
    """Devuelve la ruta absoluta del archivo de la MAIN_KEY."""
    return os.path.abspath(KEY_FILE_PATH)

# Generar y sobrescribir la MAIN_KEY en cada inicio del servidor
MAIN_KEY = generate_main_key()
