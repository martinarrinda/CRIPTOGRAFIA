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

if len(sys.argv) != 3:
    print(f"Uso: python {sys.argv[0]} <fichero> <hash_esperado>")
    sys.exit(1)

ruta = sys.argv[1]
hash_esperado = sys.argv[2].lower().strip()

if not os.path.isfile(ruta):
    print(f"Error: el fichero '{ruta}' no existe.")
    sys.exit(1)

hash_calculado = calcular_hash_fichero(ruta)

print(f"Fichero          : {ruta}")
print(f"Hash esperado    : {hash_esperado}")
print(f"Hash calculado   : {hash_calculado}")

if hash_calculado == hash_esperado:
    print("\nIntegridad verificada.")
else:
    print("\nERROR: el fichero ha sido modificado o está corrupto.")