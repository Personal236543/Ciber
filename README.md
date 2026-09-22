# Cifrado de Archivos con AES - Lab 2 Ciberseguridad

Script en Python que cifra y descifra archivos usando **AES-256 en modo CBC**,
pensado para proteger archivos antes de subirlos a un servidor FTP inseguro
(texto plano) y descifrarlos después de descargarlos.

## Requisitos

- Python 3
- Librería `pycryptodome`

Instalación de la dependencia:

```bash
pip3 install pycryptodome --break-system-packages
```

## Cómo funciona

1. El usuario ingresa una contraseña (nunca se guarda en el archivo).
2. Se genera un **salt** aleatorio (16 bytes) y un **IV** aleatorio (16 bytes).
3. Se deriva una clave AES-256 a partir de la contraseña + salt usando
   **PBKDF2** (200,000 iteraciones, SHA-256) — esto protege contra ataques
   de fuerza bruta/diccionario sobre la contraseña.
4. El archivo se cifra con AES-256-CBC.
5. El archivo de salida contiene: `salt (16 bytes) + IV (16 bytes) + datos cifrados`.

Para descifrar, el script lee el salt y el IV del propio archivo cifrado,
vuelve a derivar la clave con la contraseña que se ingrese, y descifra.

## Uso

### Cifrar un archivo (antes de subirlo al FTP)

```bash
python3 cifrado_ftp.py cifrar archivo_original.txt archivo_original.txt.enc
```

Se pedirá una contraseña. Guárdala, la necesitarás para descifrar.

### Descifrar un archivo (después de descargarlo del FTP)

```bash
python3 cifrado_ftp.py descifrar archivo_original.txt.enc archivo_recuperado.txt
```

Debes ingresar la **misma contraseña** usada al cifrar.

## Ejemplo completo (flujo real del laboratorio)

```bash
# 1. Cifrar el archivo localmente
python3 cifrado_ftp.py cifrar prueba.txt prueba.txt.enc

# 2. Subir el archivo YA CIFRADO al FTP (el FTP en sí sigue sin cifrar el canal,
#    pero el contenido del archivo ya está protegido)
ftp 192.123.10.20
> put prueba.txt.enc
> bye

# 3. Descargar el archivo cifrado desde el FTP
ftp 192.123.10.20
> get prueba.txt.enc
> bye

# 4. Descifrar localmente para recuperar el contenido original
python3 cifrado_ftp.py descifrar prueba.txt.enc prueba_recuperada.txt
```

## Notas de seguridad

- Este enfoque protege el **contenido del archivo**, pero no cifra las
  credenciales del login FTP ni los comandos del protocolo — para eso se
  necesita FTPS/SFTP (ver Fase 3 del laboratorio).
- La contraseña de cifrado debe compartirse por un canal distinto y seguro
  (no por el mismo FTP).
