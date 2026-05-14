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
            return intentos
        hashes_vistos[h] = mensaje

tamanos = [8, 10, 12, 14, 16, 18, 20]

print(f"{'Bits (N)':<12} {'Intentos hasta colisión'}")
print("-" * 36)

resultados = {}
for n in tamanos:
    intentos = buscar_colision(n)
    resultados[n] = intentos
    print(f"{n:<12} {intentos}")

print("\nGuarda estos resultados para el ejercicio 11.")