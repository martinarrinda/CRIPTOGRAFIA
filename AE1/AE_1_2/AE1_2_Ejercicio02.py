"""
=============================================================
EJERCICIO 2 – Cifrar y descifrar con AES-CBC
             usando la librería 'cryptography' (hazmat)
=============================================================
Usamos el paquete hazmat para control preciso:
  • Padding PKCS7 (ajusta el mensaje a múltiplos de 128 bits)
  • IV aleatorio por cada cifrado
  • AES en modo CBC
=============================================================
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 128  # bits (= 16 bytes)


# ─────────────────────────────────────────────────────────
# Funciones principales
# ─────────────────────────────────────────────────────────

def encrypt_aes_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Cifra 'plaintext' con AES-CBC.

    Parámetros
    ----------
    plaintext : bytes  – mensaje en claro
    key       : bytes  – clave AES (16, 24 ó 32 bytes)

    Retorna
    -------
    (iv, ciphertext) – ambos en bytes
    """
    # 1. Padding PKCS7
    padder    = padding.PKCS7(BLOCK_SIZE).padder()
    padded_pt = padder.update(plaintext) + padder.finalize()

    # 2. IV aleatorio de 16 bytes
    iv = os.urandom(16)

    # 3. Cifrado AES-CBC
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_pt) + encryptor.finalize()

    return iv, ciphertext


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifra 'ciphertext' con AES-CBC y elimina el padding PKCS7.

    Retorna el plaintext original.
    """
    # 1. Descifrado AES-CBC
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    padded_pt = decryptor.update(ciphertext) + decryptor.finalize()

    # 2. Eliminar padding PKCS7
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_pt) + unpadder.finalize()

    return plaintext


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────

def run_test(description: str, plaintext: bytes, key: bytes) -> None:
    print(f"\n  [{description}]")
    print(f"    Plaintext  : {plaintext}")

    iv, ct = encrypt_aes_cbc(plaintext, key)
    print(f"    IV (hex)   : {iv.hex()}")
    print(f"    Ciphertext : {ct.hex()}")

    recovered = decrypt_aes_cbc(ct, key, iv)
    print(f"    Recovered  : {recovered}")

    assert recovered == plaintext, "ERROR: el plaintext recuperado no coincide"
    print("    ✔  OK")


if __name__ == "__main__":
    print("=" * 55)
    print("EJERCICIO 2 – AES-CBC con librería cryptography")
    print("=" * 55)

    key_128 = os.urandom(16)   # AES-128
    key_256 = os.urandom(32)   # AES-256

    run_test("Mensaje corto (< 1 bloque)",
             b"Hola mundo",       key_128)

    run_test("Mensaje exacto 1 bloque (16 bytes)",
             b"1234567890abcdef", key_128)

    run_test("Mensaje de 2 bloques exactos (32 bytes)",
             b"A" * 32,           key_256)

    run_test("Mensaje largo con bytes no ASCII",
             "Ñoño 🔐 criptografía".encode("utf-8"), key_256)

    run_test("Mensaje vacío",
             b"",                 key_128)

    print("\n✔  Todos los tests superados.\n")