import hashlib

def hash_debil(mensaje, n_bits):
    sha1_bytes = hashlib.sha1(mensaje.encode()).digest()
    bits_totales = ""
    for byte in sha1_bytes:
        bits_totales += format(byte, "08b")
    return bits_totales[:n_bits]

mensaje = input("Introduce un mensaje: ")

for n in [8, 12, 16, 20]:
    resultado = hash_debil(mensaje, n)
    print(f"N = {n:2d} bits -> {resultado}")