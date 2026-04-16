def xor_un_byte_bytes(data, clave):
    """
    Aplica XOR con una clave de 1 byte a datos en bytes.
    
    Parámetros:
        data (bytes)
        clave (int)
    
    Retorna:
        bytes
    """
    return bytes([b ^ clave for b in data])


def es_texto_legible(texto):
    """
    Comprueba si el texto parece legible.
    """
    try:
        texto = texto.decode('utf-8')
        return all(32 <= ord(c) <= 126 or c in "áéíóúñÁÉÍÓÚÑ" for c in texto)
    except:
        return False


# Texto cifrado
hex_input = (
"fcddcbdcdd98ffd1cad7d6d998d0d9cbccd998f5cdcadbd1d9"
"9498c198dcddcbdcdd98f0cdddcbdbd998d0d9cbccd998f2d9"
"7b11d69498ddd6dbd7d6cccad9d5d7cb98d9caccdd98dbcdda"
"cad1ddd6dcd798dbd1ddd6ccd7cb98dcdd98dbcdddced9cb98"
"c198d9dacad1dfd7cb98cad7dbd7cbd7cb96"
)

data = bytes.fromhex(hex_input)

# Fuerza bruta
for clave in range(256):
    resultado = xor_un_byte_bytes(data, clave)
    
    if es_texto_legible(resultado):
        print(f"Clave: {clave}")
        print(resultado.decode('utf-8'))
        print("-" * 50)
