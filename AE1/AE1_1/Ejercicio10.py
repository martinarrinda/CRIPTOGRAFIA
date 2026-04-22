from collections import Counter

ALFABETO = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"

FRECUENCIAS_ESP = {
    'A': 12.50, 'B': 1.27, 'C': 4.43, 'D': 5.14, 'E': 13.24,
    'F': 0.79, 'G': 1.17, 'H': 0.81, 'I': 6.91, 'J': 0.45,
    'K': 0.08, 'L': 5.84, 'M': 2.61, 'N': 7.09, 'Ñ': 0.22,
    'O': 8.98, 'P': 2.75, 'Q': 0.83, 'R': 6.62, 'S': 7.44,
    'T': 4.42, 'U': 4.00, 'V': 0.98, 'W': 0.03, 'X': 0.19,
    'Y': 0.79, 'Z': 0.42
}


def normalizar_texto(texto):
    texto = texto.upper()
    return ''.join(c for c in texto if c in ALFABETO)


def desplazar_letra(letra, desplazamiento):
    i = ALFABETO.index(letra)
    return ALFABETO[(i + desplazamiento) % len(ALFABETO)]


def vigenere_descifrar(texto_cifrado, clave):
    clave = normalizar_texto(clave)
    if not clave:
        raise ValueError("La clave no puede estar vacía")

    resultado = []
    indice_clave = 0

    for c in texto_cifrado:
        if c.upper() in ALFABETO:
            k = ALFABETO.index(clave[indice_clave % len(clave)])
            resultado.append(desplazar_letra(c.upper(), -k))
            indice_clave += 1
        else:
            resultado.append(c)

    return ''.join(resultado)


def dividir_en_columnas(texto, n):
    texto = normalizar_texto(texto)
    columnas = ['' for _ in range(n)]
    for i, c in enumerate(texto):
        columnas[i % n] += c
    return columnas


def chi_cuadrado(texto):
    n = len(texto)
    if n == 0:
        return float("inf")

    contador = Counter(texto)
    chi = 0.0
    for letra in ALFABETO:
        observada = contador[letra]
        esperada = FRECUENCIAS_ESP[letra] * n / 100.0
        if esperada > 0:
            chi += ((observada - esperada) ** 2) / esperada
    return chi


def hallar_desplazamiento_probable(columna):
    mejor_despl = 0
    mejor_score = float("inf")

    for d in range(len(ALFABETO)):
        descifrado = ''.join(desplazar_letra(c, -d) for c in columna)
        score = chi_cuadrado(descifrado)
        if score < mejor_score:
            mejor_score = score
            mejor_despl = d

    return mejor_despl


def romper_vigenere_3(texto_cifrado):
    texto_normalizado = normalizar_texto(texto_cifrado)
    if len(texto_normalizado) < 3:
        raise ValueError("El texto cifrado es demasiado corto")

    columnas = dividir_en_columnas(texto_cifrado, 3)
    clave = ''.join(ALFABETO[hallar_desplazamiento_probable(col)] for col in columnas)
    mensaje = vigenere_descifrar(texto_cifrado, clave)

    return clave, mensaje


if __name__ == "__main__":
    cifrado = input("Introduce el texto cifrado: ")
    clave, mensaje = romper_vigenere_3(cifrado)
    print("Clave probable:", clave)
    print("Mensaje:", mensaje)
