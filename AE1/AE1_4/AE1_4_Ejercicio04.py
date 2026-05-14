import hashlib
import sys
import os

def calcular_hash_fichero(ruta, tamano_bloque=65536):
    sha256 = hashlib.sha256()
    with open(ruta, "rb") as f:
        while True:
            bloque = f.read(tamano_bloque)
            if not bloque:
                break
            sha256.update(bloque)
    return sha256.hexdigest()

if len(sys.argv) != 2:
    print(f"Uso: python {sys.argv[0]} <fichero>")
    sys.exit(1)

ruta = sys.argv[1]

if not os.path.isfile(ruta):
    print(f"Error: el fichero '{ruta}' no existe.")
    sys.exit(1)

resultado = calcular_hash_fichero(ruta)
print(f"Fichero : {ruta}")
print(f"SHA-256 : {resultado}")