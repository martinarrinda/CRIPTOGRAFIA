import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────────────────
# Funciones principales
# ─────────────────────────────────────────────────────────

def encrypt_aes_ctr(plaintext: bytes, key: bytes,
                    nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Cifra 'plaintext' con AES-CTR.

    Parámetros
    ----------
    plaintext : bytes        – mensaje en claro
    key       : bytes        – clave AES (16, 24 ó 32 bytes)
    nonce     : bytes | None – 16 bytes de nonce; si None, se genera uno.

    Retorna
    -------
    (nonce, ciphertext)
    """
    if nonce is None:
        nonce = os.urandom(16)   # nonce completo de 16 bytes para CTR

    assert len(nonce) == 16, "El nonce para CTR debe ser de 16 bytes"

    cipher    = Cipher(algorithms.AES(key), modes.CTR(nonce),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    ct        = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ct


def decrypt_aes_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Descifra 'ciphertext' con AES-CTR.
    CTR es simétrico: la misma operación cifra y descifra.
    """
    assert len(nonce) == 16, "El nonce para CTR debe ser de 16 bytes"
    cipher    = Cipher(algorithms.AES(key), modes.CTR(nonce),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────

def run_test(description: str, plaintext: bytes, key: bytes) -> None:
    print(f"\n  [{description}]")
    print(f"    Plaintext  : {plaintext!r}")

    nonce, ct = encrypt_aes_ctr(plaintext, key)
    print(f"    Nonce (hex): {nonce.hex()}")
    print(f"    Ciphertext : {ct.hex()}")

    recovered = decrypt_aes_ctr(ct, key, nonce)
    print(f"    Recovered  : {recovered!r}")
    assert recovered == plaintext, \
        f"FALLO: se esperaba {plaintext!r}, se obtuvo {recovered!r}"
    print("    ✔  OK")


if __name__ == "__main__":
    print("=" * 60)
    print("EJERCICIO 7 – AES-CTR con librería cryptography")
    print("=" * 60)

    key_128 = os.urandom(16)
    key_256 = os.urandom(32)

    # ── Tests básicos ──────────────────────────────────────
    run_test("Mensaje corto (< 1 bloque)",
             b"Hola CTR",         key_128)

    run_test("Exactamente 1 bloque (16 bytes)",
             b"1234567890abcdef", key_128)

    run_test("Exactamente 2 bloques (32 bytes)",
             b"A" * 32,           key_256)

    run_test("Mensaje largo (no múltiplo de 16)",
             b"La criptografia en modo CTR no necesita padding!", key_256)

    run_test("Mensaje vacío",
             b"",                 key_128)

    run_test("Un solo byte",
             b"X",               key_128)

    # ── Verificar que reutilizar nonce+key es peligroso ────
    print("\n─" * 30)
    print("  Demostración: XOR attack con nonce reutilizado")
    print("─" * 30)

    key   = os.urandom(16)
    nonce = os.urandom(16)

    pt1 = b"Secreto de Alicia!"
    pt2 = b"Mensaje falso Bob?"

    _, ct1 = encrypt_aes_ctr(pt1, key, nonce)   # mismo nonce y clave
    _, ct2 = encrypt_aes_ctr(pt2, key, nonce)   # ← NUNCA HACER ESTO

    # XOR de los dos ciphertexts = XOR de los dos plaintexts
    L    = min(len(ct1), len(ct2))
    xor  = bytes(a ^ b for a, b in zip(ct1[:L], ct2[:L]))
    pt_xor = bytes(a ^ b for a, b in zip(pt1[:L], pt2[:L]))

    print(f"  XOR(CT1, CT2) = {xor.hex()}")
    print(f"  XOR(PT1, PT2) = {pt_xor.hex()}")
    assert xor == pt_xor, "ERROR: XOR(CT1,CT2) ≠ XOR(PT1,PT2)"
    print("  ✔  XOR(CT1,CT2) == XOR(PT1,PT2) → "
          "reutilizar nonce filtra información del plaintext!\n")