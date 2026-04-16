from itertools import combinations
from collections import Counter

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

FRECUENCIAS_INGLES = {
    'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 12.7,
    'F': 2.2, 'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15,
    'K': 0.77, 'L': 4.0, 'M': 2.4, 'N': 6.7, 'O': 7.5,
    'P': 1.9, 'Q': 0.095, 'R': 6.0, 'S': 6.3, 'T': 9.1,
    'U': 2.8, 'V': 1.0, 'W': 2.4, 'X': 0.15, 'Y': 2.0,
    'Z': 0.074
}

# ---------------------------
# NORMALIZAR TEXTO
# ---------------------------
def normalizar(texto):
    return ''.join(c for c in texto.upper() if c in ALFABETO)

# ---------------------------
# HAMMING DISTANCE
# ---------------------------
def hamming_distance_bytes(b1, b2):
    if len(b1) != len(b2):
        raise ValueError("Los bytes deben tener la misma longitud")
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))


def hamming_distance(t1, t2):
    if len(t1) != len(t2):
        raise ValueError("Las cadenas deben tener la misma longitud")
    return hamming_distance_bytes(t1.encode(), t2.encode())

# ---------------------------
# DIVIDIR EN BLOQUES
# ---------------------------
def dividir_bloques(texto, tam):
    return [texto[i:i + tam] for i in range(0, len(texto), tam)
            if len(texto[i:i + tam]) == tam]

# ---------------------------
# DISTANCIA NORMALIZADA
# ---------------------------
# Versión 3: comparar todos los pares posibles entre los bloques disponibles
# (o hasta un número razonable de bloques para evitar combinaciones excesivas).
def distancia_media_normalizada(texto, tam, max_bloques=8):
    bloques = dividir_bloques(texto, tam)

    if len(bloques) < 2:
        return float("inf")

    bloques = bloques[:max_bloques]
    pares = list(combinations(bloques, 2))
    distancias = [hamming_distance(a, b) / tam for a, b in pares]

    return sum(distancias) / len(distancias)

# ---------------------------
# MEJORES TAMAÑOS
# ---------------------------
def mejores_tamaños_clave(texto, max_tam=40, top=5):
    texto = normalizar(texto)
    resultados = []

    for tam in range(2, max_tam + 1):
        score = distancia_media_normalizada(texto, tam)
        resultados.append((tam, score))

    resultados.sort(key=lambda x: x[1])
    return resultados[:top]

# ---------------------------
# CHI-CUADRADO
# ---------------------------
def chi_cuadrado(texto):
    N = len(texto)
    conteo = Counter(texto)
    chi = 0

    for letra in ALFABETO:
        observado = conteo.get(letra, 0)
        esperado = FRECUENCIAS_INGLES[letra] * N / 100
        if esperado > 0:
            chi += ((observado - esperado) ** 2) / esperado

    return chi

# ---------------------------
# MEJOR DESPLAZAMIENTO
# ---------------------------
def mejor_desplazamiento(columna):
    mejor = 0
    mejor_score = float("inf")

    for d in range(26):
        descifrado = ''.join(
            chr((ord(c) - ord('A') - d) % 26 + ord('A'))
            for c in columna
        )
        score = chi_cuadrado(descifrado)
        if score < mejor_score:
            mejor_score = score
            mejor = d

    return mejor

# ---------------------------
# ROMPER VIGENERE
# ---------------------------
def romper_vigenere(texto, tam_clave):
    texto = normalizar(texto)
    columnas = ['' for _ in range(tam_clave)]

    for i, c in enumerate(texto):
        columnas[i % tam_clave] += c

    clave = ''.join(chr(mejor_desplazamiento(col) + ord('A')) for col in columnas)
    return clave

# ---------------------------
# DESCIFRAR
# ---------------------------
def descifrar(texto, clave):
    texto = normalizar(texto)
    clave = normalizar(clave)

    resultado = []
    for i, c in enumerate(texto):
        k = ord(clave[i % len(clave)]) - ord('A')
        p = (ord(c) - ord('A') - k) % 26
        resultado.append(chr(p + ord('A')))

    return ''.join(resultado)

# ---------------------------
# FUNCIONES DE PRESENTACIÓN
# ---------------------------
def mostrar_candidatos(candidatos, texto_normalizado):
    resultados = []
    print("\nPosibles tamaños de clave:\n")

    for i, (tam, score) in enumerate(candidatos):
        clave = romper_vigenere(texto_normalizado, tam)
        descifrado = descifrar(texto_normalizado, clave)
        resultados.append((tam, clave, descifrado))
        print(f"{i}: Tamaño = {tam} | Score = {score:.4f} | Clave = {clave}")
        print(f"   Texto parcial: {descifrado[:100]}\n")

    return resultados

# ---------------------------
# FUNCIÓN PRINCIPAL
# ---------------------------
def analizar_vigenere(texto):
    texto_normalizado = normalizar(texto)

    if len(texto_normalizado) < 40:
        print("Texto algo corto, los resultados pueden no ser fiables.\n")

    candidatos = mejores_tamaños_clave(texto_normalizado)
    resultados = mostrar_candidatos(candidatos, texto_normalizado)

    while True:
        try:
            opcion = int(input("Elige el índice del candidato (0-4): "))
            if 0 <= opcion < len(resultados):
                break
            print("Índice inválido. Elige un número entre 0 y 4.")
        except ValueError:
            print("Entrada inválida. Introduce un número entero.")

    tam, clave, texto_descifrado = resultados[opcion]
    print("\n--- RESULTADO FINAL ---")
    print(f"Tamaño de clave elegido: {tam}")
    print(f"Clave: {clave}")
    print(f"Texto descifrado:\n{texto_descifrado}")

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    texto = input("Introduce el texto cifrado:\n")
    analizar_vigenere(texto)
