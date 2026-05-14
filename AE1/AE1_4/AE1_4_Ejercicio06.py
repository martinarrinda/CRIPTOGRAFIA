import hashlib
import sys
import os

HASH_OFICIAL = "d1618b5b092292ee334c6f9c0d67d3d749d8612e624a7890c51b8d3d90f4b761"

NOMBRE_FICHERO = "Python-3.13.3.tar.xz"

URL_OFICIAL = "https://www.python.org/ftp/python/3.13.3/Python-3.13.3.tar.xz"
URL_HASHES = "https://www.python.org/downloads/release/python-3133/"

def calcular_hash_fichero(ruta, tamano_bloque=65536):
    sha256 = hashlib.sha256()

    with open(ruta, "rb") as f:
        while True:
            bloque = f.read(tamano_bloque)

            if not bloque:
                break

            sha256.update(bloque)

    return sha256.hexdigest()

def verificar_integridad():
    print("=" * 60)
    print(" Verificación de integridad de software descargado")
    print("=" * 60)
    print(f"Programa  : Python 3.13.3")
    print(f"Fichero   : {NOMBRE_FICHERO}")
    print(f"Fuente    : {URL_OFICIAL}")
    print(f"Hashes en : {URL_HASHES}")
    print("=" * 60)
    print()

    if len(sys.argv) != 2:
        print(f"Uso: python {sys.argv[0]} <fichero>")
        sys.exit(1)

    ruta = sys.argv[1]

    if not os.path.isfile(ruta):
        print(f"Error: el fichero '{ruta}' no existe.")
        sys.exit(1)

    hash_calculado = calcular_hash_fichero(ruta)

    print(f"Hash oficial   : {HASH_OFICIAL}")
    print(f"Hash calculado : {hash_calculado}")
    print()

    if hash_calculado == HASH_OFICIAL:
        print("RESULTADO: Integridad verificada.")
        print("El fichero es auténtico y no ha sido modificado.")
    else:
        print("RESULTADO: ERROR")
        print("El fichero puede estar corrupto o manipulado.")

if __name__ == "__main__":
    verificar_integridad()