
BLOCK_SIZE = 16  # AES usa bloques de 16 bytes


# ─────────────────────────────────────────────────────────
# Implementación manual
# ─────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Aplica PKCS#7 padding a 'data'.
    Siempre añade entre 1 y block_size bytes.
    """
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size debe estar entre 1 y 255")

    # Número de bytes de relleno necesarios
    pad_len = block_size - (len(data) % block_size)
    # pad_len está en [1, block_size] por construcción
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Elimina el PKCS#7 padding de 'data'.
    Lanza ValueError si el padding no es válido.
    """
    if len(data) == 0:
        raise ValueError("El dato está vacío, no se puede quitar padding")
    if len(data) % block_size != 0:
        raise ValueError(f"La longitud {len(data)} no es múltiplo de {block_size}")

    pad_len = data[-1]  # El último byte indica cuántos bytes de padding hay

    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Padding inválido: valor {pad_len}")

    # Verificar que todos los bytes de padding tienen el valor correcto
    padding_bytes = data[-pad_len:]
    if padding_bytes != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 corrupto")

    return data[:-pad_len]


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────

def test_roundtrip(plaintext: bytes) -> None:
    """Verifica que unpad(pad(pt)) == pt"""
    padded   = pkcs7_pad(plaintext)
    unpadded = pkcs7_unpad(padded)
    assert unpadded == plaintext, (
        f"FALLO: se esperaba {plaintext!r}, se obtuvo {unpadded!r}"
    )

    # Mostrar resultado
    pad_len = padded[-1]
    print(f"  len={len(plaintext):2d} bytes │ "
          f"padding={pad_len:2d} bytes │ "
          f"padded len={len(padded):2d} bytes │ ✔")


if __name__ == "__main__":
    print("=" * 60)
    print("EJERCICIO 3 – PKCS#7 Padding / Unpadding manual")
    print("=" * 60)

    # ── Tests del enunciado ───────────────────────────────
    test_cases = [
        (12, b"A" * 12),
        (16, b"A" * 16),
        (20, b"A" * 20),
        (32, b"A" * 32),
        (64, b"A" * 64),
    ]

    print(f"\n{'Tamaño':>7}  {'Relleno':>8}  {'Total':>6}  {'OK':>4}")
    print("-" * 40)
    for size, data in test_cases:
        test_roundtrip(data)

    # ── Tests extra con texto real ───────────────────────
    print("\n  Mensajes de texto real:")
    for msg in [b"", b"Hola", b"1234567890abcdef", b"Criptografia"]:
        test_roundtrip(msg)
        pad_len = pkcs7_pad(msg)[-1]
        print(f"    {msg!r:30s} → padding añadido: {pad_len} bytes")

    # ── Verificar que el padding es siempre válido ───────
    print("\n  Comprobación visual del padding:")
    msg = b"HELLO"
    padded = pkcs7_pad(msg)
    print(f"    Original  : {list(msg)}")
    print(f"    Padded    : {list(padded)}")
    print(f"    Hex       : {padded.hex()}")
    assert pkcs7_unpad(padded) == msg

    # ── Tests de padding inválido ─────────────────────────
    print("\n  Tests de padding inválido (deben lanzar ValueError):")
    casos_invalidos = [
        b"\x00" * 16,        # padding 0x00 no es válido
        b"\x05" * 15 + b"\x06",  # último byte no coincide con el resto
        b"A" * 17,           # longitud no múltiplo de 16
    ]
    for caso in casos_invalidos:
        try:
            pkcs7_unpad(caso)
            print(f"    ✘ Debería haber fallado: {caso.hex()}")
        except ValueError as e:
            print(f"    ✔ ValueError correctamente lanzado: {e}")

    print("\n✔  Todos los tests de Ejercicio 3 superados.\n")