import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as lib_padding

# Importamos las funciones del Ejercicio 3 (inline para ser autocontenido)

BLOCK_SIZE = 16


# ─────────────────────────────────────────────────────────
# Primitivas de bloque (usan AES-ECB internamente)
# ─────────────────────────────────────────────────────────

def aes_enc(block: bytes, key: bytes) -> bytes:
    """Cifra UN bloque de 16 bytes con AES-ECB (sin padding)."""
    assert len(block) == 16, "aes_enc requiere exactamente 16 bytes"
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_dec(block: bytes, key: bytes) -> bytes:
    """Descifra UN bloque de 16 bytes con AES-ECB (sin padding)."""
    assert len(block) == 16, "aes_dec requiere exactamente 16 bytes"
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()


# ─────────────────────────────────────────────────────────
# PKCS7 (copiado del Ejercicio 3 para ser autocontenido)
# ─────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Padding inválido: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 corrupto")
    return data[:-pad_len]


# ─────────────────────────────────────────────────────────
# Cifrado CBC manual
# ─────────────────────────────────────────────────────────

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de dos cadenas de igual longitud."""
    assert len(a) == len(b), "Las cadenas deben tener la misma longitud"
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_aes_cbc_manual(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Cifrado AES-CBC implementado manualmente.

    Pasos:
      1. Aplicar PKCS7 padding al plaintext.
      2. Dividir en bloques de 16 bytes.
      3. Para cada bloque:
           bloque_xor = P[i] XOR C[i-1]   (o IV para i=0)
           C[i]       = AES_ECB_Enc(bloque_xor, key)
      4. Concatenar todos los C[i].
    """
    assert len(iv) == 16, "IV debe ser de 16 bytes"

    # 1. Padding
    padded = pkcs7_pad(plaintext)

    # 2. Dividir en bloques
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]

    # 3. Encadenar y cifrar
    ciphertext = b""
    prev_block = iv
    for block in blocks:
        xored      = xor_bytes(block, prev_block)  # CBC XOR
        encrypted  = aes_enc(xored, key)           # AES-ECB puro
        ciphertext += encrypted
        prev_block  = encrypted

    return ciphertext


# ─────────────────────────────────────────────────────────
# Referencia: CBC nativo de la librería
# ─────────────────────────────────────────────────────────

def encrypt_aes_cbc_lib(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """CBC nativo de cryptography (con padding PKCS7 de la librería)."""
    padder    = lib_padding.PKCS7(128).padder()
    padded    = padder.update(plaintext) + padder.finalize()
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


# ─────────────────────────────────────────────────────────
# TESTS – verificación de igualdad
# ─────────────────────────────────────────────────────────

def test_encrypt(description: str, plaintext: bytes,
                 key: bytes, iv: bytes) -> None:
    manual = encrypt_aes_cbc_manual(plaintext, key, iv)
    lib    = encrypt_aes_cbc_lib(plaintext, key, iv)

    match = "✔" if manual == lib else "✘"
    print(f"\n  [{description}]")
    print(f"    Plaintext : {plaintext!r}")
    print(f"    Manual    : {manual.hex()}")
    print(f"    Librería  : {lib.hex()}")
    print(f"    Coinciden : {match}")
    assert manual == lib, (
        f"FALLO en '{description}': manual ≠ librería"
    )


if __name__ == "__main__":
    print("=" * 60)
    print("EJERCICIO 4 – Cifrado AES-CBC manual vs. librería")
    print("=" * 60)

    key = os.urandom(16)
    iv  = os.urandom(16)

    test_encrypt("Mensaje corto (< 1 bloque)",
                 b"Hola mundo",       key, iv)

    test_encrypt("1 bloque exacto (16 bytes)",
                 b"1234567890abcdef", key, iv)

    test_encrypt("2 bloques exactos (32 bytes)",
                 b"A" * 32,           key, iv)

    test_encrypt("3 bloques + sobrante",
                 b"Criptografia AES en modo CBC manual!", key, iv)

    test_encrypt("Mensaje vacío",
                 b"",                 key, iv)

    print("\n✔  Todos los tests del Ejercicio 4 superados.")
    print("   El CBC manual produce resultados IDÉNTICOS a la librería.\n")