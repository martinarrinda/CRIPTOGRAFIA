from collections import Counter
from itertools import combinations

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

FRECUENCIAS = {
    "ingles": {
        'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 12.7,
        'F': 2.2, 'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15,
        'K': 0.77, 'L': 4.0, 'M': 2.4, 'N': 6.7, 'O': 7.5,
        'P': 1.9, 'Q': 0.095, 'R': 6.0, 'S': 6.3, 'T': 9.1,
        'U': 2.8, 'V': 1.0, 'W': 2.4, 'X': 0.15, 'Y': 2.0,
        'Z': 0.074
    },
    "espanol": {
        'A': 12.5, 'B': 1.5, 'C': 4.0, 'D': 5.0, 'E': 13.7,
        'F': 0.7, 'G': 1.0, 'H': 0.7, 'I': 6.2, 'J': 0.5,
        'K': 0.0, 'L': 4.9, 'M': 3.1, 'N': 6.7, 'O': 8.7,
        'P': 2.5, 'Q': 0.9, 'R': 6.9, 'S': 7.9, 'T': 4.6,
        'U': 3.9, 'V': 1.0, 'W': 0.0, 'X': 0.2, 'Y': 1.5,
        'Z': 0.5
    }
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
def distancia_media_normalizada(texto, tam, max_bloques=8):
    bloques = dividir_bloques(texto, tam)
    if len(bloques) < 2:
        return float('inf')
    bloques = bloques[:max_bloques]
    pares = list(combinations(bloques, 2))
    distancias = [hamming_distance(a, b) / tam for a, b in pares]
    return sum(distancias) / len(distancias)

# ---------------------------
# MEJORES TAMAÑOS DE CLAVE
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
def chi_cuadrado(texto, idioma):
    N = len(texto)
    if N == 0:
        return float('inf')
    conteo = Counter(texto)
    chi = 0
    frec = FRECUENCIAS[idioma]
    for letra in ALFABETO:
        observado = conteo.get(letra, 0)
        esperado = frec.get(letra, 0) * N / 100
        if esperado > 0:
            chi += ((observado - esperado) ** 2) / esperado
    return chi

# ---------------------------
# MEJOR DESPLAZAMIENTO
# ---------------------------
def mejor_desplazamiento_por_idioma(columna, idioma):
    mejor_d = 0
    mejor_score = float('inf')
    for d in range(26):
        descifrado = ''.join(
            chr((ord(ch) - ord('A') - d) % 26 + ord('A'))
            for ch in columna
        )
        score = chi_cuadrado(descifrado, idioma)
        if score < mejor_score:
            mejor_score = score
            mejor_d = d
    return mejor_d

# ---------------------------
# ROMPER VIGENERE POR IDIOMA
# ---------------------------
def romper_vigenere_por_idioma(texto_cifrado, tam_clave, idioma):
    texto = normalizar(texto_cifrado)
    columnas = ['' for _ in range(tam_clave)]
    for i, c in enumerate(texto):
        columnas[i % tam_clave] += c
    clave = ''
    for col in columnas:
        clave += chr(mejor_desplazamiento_por_idioma(col, idioma) + ord('A'))
    descifrado = []
    for i, c in enumerate(texto):
        k = ord(clave[i % len(clave)]) - ord('A')
        descifrado.append(chr((ord(c) - ord('A') - k) % 26 + ord('A')))
    return clave, ''.join(descifrado)

# ---------------------------
# EVALUAR CANDIDATOS
# ---------------------------
def evaluar_candidatos(texto_cifrado, candidatos_tam, top=5):
    resultados = []
    for tam in candidatos_tam:
        for idioma in FRECUENCIAS:
            clave, mensaje = romper_vigenere_por_idioma(texto_cifrado, tam, idioma)
            score = chi_cuadrado(mensaje, idioma)
            resultados.append((tam, idioma, clave, score, mensaje))
    resultados.sort(key=lambda x: x[3])
    return resultados[:top]

# ---------------------------
# MOSTRAR CANDIDATOS
# ---------------------------
def presentar_candidatos(resultados):
    print("\nCinco claves más probables:")
    for i, (tam, idioma, clave, score, mensaje) in enumerate(resultados):
        print(f"{i}. Tamaño={tam}, idioma={idioma}, clave={clave}, chi2={score:.2f}")
        print(f"   Texto parcial: {mensaje[:80]}")
    print("\nEl candidato más probable será el primero listado.")

# ---------------------------
# FUNCIÓN PRINCIPAL
# ---------------------------
def analizar_vigenere(texto):
    texto_normalizado = normalizar(texto)
    if len(texto_normalizado) < 40:
        print("Texto algo corto, los resultados pueden no ser fiables.\n")
    mejores_tam = mejores_tamaños_clave(texto_normalizado)
    candidatos_tam = [tam for tam, _ in mejores_tam]
    print("Tamaños de clave más probables:")
    for tam, score in mejores_tam:
        print(f"Tamaño={tam}, distancia normalizada={score:.4f}")
    resultados = evaluar_candidatos(texto_normalizado, candidatos_tam)
    presentar_candidatos(resultados)
    tam_mejor, idioma_mejor, clave_mejor, _, mensaje_mejor = resultados[0]
    print("\n--- RESULTADO FINAL ---")
    print(f"Tamaño de clave elegido: {tam_mejor}")
    print(f"Idioma probable: {idioma_mejor}")
    print(f"Clave probable: {clave_mejor}")
    print("Mensaje descifrado:\n")
    print(mensaje_mejor)
    print("\nIdentifica a qué se refiere el mensaje leyendo el texto descifrado.")

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    texto = input("Introduce el texto cifrado:\n")
    analizar_vigenere(texto)
