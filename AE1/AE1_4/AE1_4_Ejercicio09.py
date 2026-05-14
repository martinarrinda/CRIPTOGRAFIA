import hashlib
import random
import string

def hash_debil(mensaje, n_bits):
    sha1_bytes = hashlib.sha1(mensaje.encode()).digest()
    bits_totales = ""
    for byte in sha1_bytes:
        bits_totales += format(byte, "08b")
    return bits_totales[:n_bits]

def generar_mensaje_aleatorio(longitud=10):
    caracteres = string.ascii_letters + string.digits
    return "".join(random.choices(caracteres, k=longitud))

def buscar_colision(n_bits):
    hashes_vistos = {}
    intentos = 0

    while True:
        mensaje = generar_mensaje_aleatorio()
        h = hash_debil(mensaje, n_bits)
        intentos += 1

        if h in hashes_vistos and hashes_vistos[h] != mensaje:
            return mensaje, hashes_vistos[h], h, intentos

        hashes_vistos[h] = mensaje

n_bits = int(input("Número de bits para el hash débil: "))

print(f"\nBuscando colisión con hash de {n_bits} bits...")
msg1, msg2, hash_col, intentos = buscar_colision(n_bits)

print(f"\n--- Colisión encontrada ---")
print(f"Mensaje 1      : {msg1}")
print(f"Mensaje 2      : {msg2}")
print(f"Hash repetido  : {hash_col}")
print(f"Intentos       : {intentos}")