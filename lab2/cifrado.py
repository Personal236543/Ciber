#!/usr/bin/env python3
"""
cifrado_ftp.py
Lab 2 - Ciberseguridad - Universidad de los Andes
Cifra/descifra archivos con AES (modo CBC) antes de subirlos/bajarlos por FTP.

Uso:
    python3 cifrado_ftp.py cifrar   <archivo_entrada> <archivo_salida.enc>
    python3 cifrado_ftp.py descifrar <archivo_entrada.enc> <archivo_salida>
"""

import sys
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import getpass

# --- Configuración ---
SALT_SIZE = 16      # bytes
IV_SIZE = 16         # bytes (tamaño de bloque de AES)
KEY_SIZE = 32        # AES-256
PBKDF2_ITERATIONS = 200_000


def derivar_clave(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 a partir de una contraseña usando PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS,
                   hmac_hash_module=SHA256)


def cifrar_archivo(ruta_entrada: str, ruta_salida: str, password: str):
    """Cifra un archivo con AES-256-CBC. Antepone salt + IV al archivo cifrado."""
    with open(ruta_entrada, "rb") as f:
        datos = f.read()

    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    clave = derivar_clave(password, salt)

    cifrador = AES.new(clave, AES.MODE_CBC, iv)
    datos_cifrados = cifrador.encrypt(pad(datos, AES.block_size))

    with open(ruta_salida, "wb") as f:
        f.write(salt + iv + datos_cifrados)

    print(f"[OK] Archivo cifrado guardado en: {ruta_salida}")
    print(f"     Tamaño original: {len(datos)} bytes")
    print(f"     Tamaño cifrado : {len(salt) + len(iv) + len(datos_cifrados)} bytes")


def descifrar_archivo(ruta_entrada: str, ruta_salida: str, password: str):
    """Descifra un archivo cifrado por esta misma herramienta."""
    with open(ruta_entrada, "rb") as f:
        contenido = f.read()

    salt = contenido[:SALT_SIZE]
    iv = contenido[SALT_SIZE:SALT_SIZE + IV_SIZE]
    datos_cifrados = contenido[SALT_SIZE + IV_SIZE:]

    clave = derivar_clave(password, salt)
    descifrador = AES.new(clave, AES.MODE_CBC, iv)

    try:
        datos = unpad(descifrador.decrypt(datos_cifrados), AES.block_size)
    except ValueError:
        print("[ERROR] No se pudo descifrar: contraseña incorrecta o archivo corrupto.")
        sys.exit(1)

    with open(ruta_salida, "wb") as f:
        f.write(datos)

    print(f"[OK] Archivo descifrado guardado en: {ruta_salida}")


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)

    modo, entrada, salida = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.isfile(entrada):
        print(f"[ERROR] El archivo de entrada no existe: {entrada}")
        sys.exit(1)

    password = getpass.getpass("Ingrese la contraseña de cifrado: ")

    if modo == "cifrar":
        cifrar_archivo(entrada, salida, password)
    elif modo == "descifrar":
        descifrar_archivo(entrada, salida, password)
    else:
        print("[ERROR] Modo no reconocido. Use 'cifrar' o 'descifrar'.")
        sys.exit(1)


if __name__ == "__main__":
    main()