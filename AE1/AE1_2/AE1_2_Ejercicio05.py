import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as lib_padding

BLOCK_SIZE = 16


# ─────────────────────────────────────────────────────────
# Primitivas (idénticas al Ejercicio 4)
# ─────────────────────────────────────────────────────────

def aes_enc(block: bytes, key: bytes) -> bytes:
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_dec(block: bytes, key: bytes) -> bytes:
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ─────────────────────────────────────────────────────────
# PKCS7
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
# Cifrado CBC manual (del Ejercicio 4)
# ─────────────────────────────────────────────────────────

def encrypt_aes_cbc_manual(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded  = pkcs7_pad(plaintext)
    blocks  = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    ct      = b""
    prev    = iv
    for block in blocks:
        enc  = aes_enc(xor_bytes(block, prev), key)
        ct  += enc
        prev = enc
    return ct


# ─────────────────────────────────────────────────────────
# Descifrado CBC manual  ← EJERCICIO 5
# ─────────────────────────────────────────────────────────

def decrypt_aes_cbc_manual(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Descifrado AES-CBC implementado manualmente.

    Pasos:
      1. Dividir ciphertext en bloques de 16 bytes.
      2. Para cada bloque C[i]:
           decrypted  = AES_ECB_Dec(C[i], key)
           P[i]       = decrypted XOR C[i-1]   (o IV para i=0)
      3. Eliminar padding PKCS7 del plaintext resultante.
    """
    assert len(ciphertext) % BLOCK_SIZE == 0, \
        "El ciphertext debe ser múltiplo de 16 bytes"
    assert len(iv) == BLOCK_SIZE, "IV debe ser de 16 bytes"

    # 1. Dividir en bloques
    blocks = [ciphertext[i:i + BLOCK_SIZE]
              for i in range(0, len(ciphertext), BLOCK_SIZE)]

    # 2. Descifrar bloque a bloque
    plaintext_padded = b""
    prev_block = iv
    for block in blocks:
        decrypted         = aes_dec(block, key)      # AES-ECB puro
        plaintext_block   = xor_bytes(decrypted, prev_block)  # XOR CBC
        plaintext_padded += plaintext_block
        prev_block        = block                    # el bloque cifrado anterior

    # 3. Quitar padding
    return pkcs7_unpad(plaintext_padded)


# ─────────────────────────────────────────────────────────
# Referencia: descifrado nativo de la librería
# ─────────────────────────────────────────────────────────

def decrypt_aes_cbc_lib(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder  = lib_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ─────────────────────────────────────────────────────────
# Cifrado con librería (para generar ciphertexts de prueba)
# ─────────────────────────────────────────────────────────

def encrypt_aes_cbc_lib(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = lib_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    enc    = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────

def test_decrypt(description: str, plaintext: bytes,
                 key: bytes, iv: bytes) -> None:
    print(f"\n  [{description}]")
    print(f"    Plaintext original : {plaintext!r}")

    # Cifrar con nuestra implementación manual del Ej.4
    ct = encrypt_aes_cbc_manual(plaintext, key, iv)
    print(f"    Ciphertext (hex)   : {ct.hex()}")

    # Descifrar con nuestra implementación manual (Ej.5)
    recovered_manual = decrypt_aes_cbc_manual(ct, key, iv)
    # Descifrar con la librería (referencia)
    recovered_lib    = decrypt_aes_cbc_lib(ct, key, iv)

    print(f"    Manual descifrado  : {recovered_manual!r}")
    print(f"    Librería descifrado: {recovered_lib!r}")

    assert recovered_manual == plaintext, \
        f"FALLO: manual ≠ original en '{description}'"
    assert recovered_lib == plaintext, \
        f"FALLO: librería ≠ original en '{description}'"
    assert recovered_manual == recovered_lib, \
        f"FALLO: manual ≠ librería en '{description}'"
    print("    ✔  OK – manual == librería == original")


def test_decrypt_from_lib_ct(description: str, plaintext: bytes,
                             key: bytes, iv: bytes) -> None:
    """El ciphertext es generado por la librería y lo descifra el manual."""
    print(f"\n  [{description} – CT generado por librería]")
    ct = encrypt_aes_cbc_lib(plaintext, key, iv)
    recovered = decrypt_aes_cbc_manual(ct, key, iv)
    assert recovered == plaintext, \
        f"FALLO: manual no pudo descifrar CT de librería en '{description}'"
    print(f"    ✔  Manual descifra correctamente CT de librería: {recovered!r}")


if __name__ == "__main__":
    print("=" * 60)
    print("EJERCICIO 5 – Descifrado AES-CBC manual")
    print("=" * 60)

    key = os.urandom(16)
    iv  = os.urandom(16)

    # Test completo: encrypt_manual → decrypt_manual
    test_decrypt("Mensaje corto",
                 b"Hola mundo",       key, iv)
    test_decrypt("1 bloque exacto",
                 b"1234567890abcdef", key, iv)
    test_decrypt("2 bloques exactos",
                 b"A" * 32,           key, iv)
    test_decrypt("Mensaje largo",
                 b"La criptografia es fascinante!!", key, iv)
    test_decrypt("Mensaje vacío",
                 b"",                 key, iv)

    # Test cruzado: librería cifra, manual descifra
    test_decrypt_from_lib_ct("Cross-test 1",
                             b"Interoperabilidad!", key, iv)
    test_decrypt_from_lib_ct("Cross-test 2",
                             b"B" * 48,            key, iv)

    print("\n✔  Todos los tests del Ejercicio 5 superados.\n")