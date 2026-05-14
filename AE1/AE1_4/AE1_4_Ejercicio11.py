import hashlib
import random
import string
import matplotlib.pyplot as plt

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

print("Ejecutando experimento de colisiones...\n")
print(f"{'Bits (N)':<12} {'Intentos':<15} {'2^(N/2) teórico'}")
print("-" * 45)

resultados = []
for n in tamanos:
    intentos = buscar_colision(n)
    teorico = int(2 ** (n / 2))
    resultados.append(intentos)
    print(f"{n:<12} {intentos:<15} {teorico}")

print("\nGenerando gráfica...")

plt.figure(figsize=(9, 5))
plt.plot(tamanos, resultados, marker="o", color="steelblue", linewidth=2, label="Intentos reales")
plt.plot(tamanos, [int(2 ** (n / 2)) for n in tamanos], marker="s", linestyle="--",
         color="tomato", linewidth=1.5, label="Teórico 2^(N/2)")
plt.xlabel("Número de bits (N)")
plt.ylabel("Intentos hasta colisión")
plt.title("Análisis de Colisiones - Bits vs Intentos")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("grafica_colisiones.png", dpi=150)
plt.show()