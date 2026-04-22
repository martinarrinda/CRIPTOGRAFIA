def xor_hex_con_padding(hex1, hex2):
    """
    XOR entre dos hexadecimales aplicando padding automático.
    """
    # Quitamos '0x'
    h1 = hex1[2:]
    h2 = hex2[2:]
    
    # Igualamos longitudes
    max_len = max(len(h1), len(h2))
    h1 = h1.zfill(max_len)
    h2 = h2.zfill(max_len)
    
    # Convertimos a bytes
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    
    # XOR byte a byte
    resultado = bytes([x ^ y for x, y in zip(b1, b2)])
    
    return resultado.hex()


# Ejemplo importante
print(xor_hex_con_padding("0xa478020098", "0x930870"))
