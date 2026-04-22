def vigenere_cifrar(texto, clave):
    """
    Cifra usando Vigenère.
    
    Parámetros:
        texto (str)
        clave (str)
    """
    resultado = ""
    clave = clave.upper()
    texto = texto.upper()
    
    j = 0
    for i in range(len(texto)):
        if texto[i].isalpha():
            desplazamiento = ord(clave[j % len(clave)]) - ord('A')
            nueva = (ord(texto[i]) - ord('A') + desplazamiento) % 26
            resultado += chr(nueva + ord('A'))
            j += 1
        else:
            resultado += texto[i]
    
    return resultado


def vigenere_descifrar(texto, clave):
    resultado = ""
    clave = clave.upper()
    texto = texto.upper()
    
    j = 0
    for i in range(len(texto)):
        if texto[i].isalpha():
            desplazamiento = ord(clave[j % len(clave)]) - ord('A')
            nueva = (ord(texto[i]) - ord('A') - desplazamiento) % 26
            resultado += chr(nueva + ord('A'))
            j += 1
        else:
            resultado += texto[i]
    
    return resultado


# Ejemplo
mensaje = "HOLA"
clave = "KEY"

cifrado = vigenere_cifrar(mensaje, clave)
descifrado = vigenere_descifrar(cifrado, clave)

print("Cifrado:", cifrado)
print("Descifrado:", descifrado)