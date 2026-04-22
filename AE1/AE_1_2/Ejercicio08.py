import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE   = 16
NONCE_BYTES  = 8   # 8 bytes de nonce
COUNTER_BYTES = 8  # 8 bytes de contador


# ─────────────────────────────────────────────────────────
# Primitiva AES-ECB para un bloque
# ─────────────────────────────────────────────────────────

def aes_enc_block(block: bytes, key: bytes) -> bytes:
    """Cifra exactamente 16 bytes con AES-ECB."""
    assert len(block) == 16
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


# ─────────────────────────────────────────────────────────
# CTR manual
# ─────────────────────────────────────────────────────────

def _build_counter_block(nonce: bytes, counter: int) -> bytes:
    """
    Construye el bloque de entrada al AES:
    nonce (8 bytes, big-endian) || counter (8 bytes, big-endian)
    """
    assert len(nonce) == NONCE_BYTES
    return nonce + counter.to_bytes(COUNTER_BYTES, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ctr_manual(data: bytes, key: bytes,
                   nonce: bytes, initial_counter: int = 0) -> bytes:
    """
    Cifra O descifra 'data' con AES-CTR manual.
    (En CTR cifrar == descifrar: es XOR con el keystream.)

    Parámetros
    ----------
    data            : bytes – plaintext o ciphertext
    key             : bytes – clave AES (16, 24 ó 32 bytes)
    nonce           : bytes – 8 bytes de nonce
    initial_counter : int   – valor inicial del contador (default 0)

    Retorna
    -------
    bytes – ciphertext (o plaintext si se le pasa ciphertext)
    """
    assert len(nonce) == NONCE_BYTES, \
        f"Nonce debe ser {NONCE_BYTES} bytes, recibido {len(nonce)}"

    result  = b""
    counter = initial_counter
    offset  = 0

    while offset < len(data):
        # 1. Construir bloque contador
        counter_block = _build_counter_block(nonce, counter)

        # 2. Cifrar el bloque contador con AES-ECB → keystream
        keystream = aes_enc_block(counter_block, key)

        # 3. XOR del trozo de datos con el keystream
        chunk = data[offset: offset + BLOCK_SIZE]
        result += _xor_bytes(chunk, keystream[:len(chunk)])

        counter += 1
        offset  += BLOCK_SIZE

    return result


# ─────────────────────────────────────────────────────────
# Referencia: librería cryptography en modo CTR
# ─────────────────────────────────────────────────────────

def aes_ctr_lib(data: bytes, key: bytes,
                nonce_8: bytes, initial_counter: int = 0) -> bytes:
    """
    CTR de la librería, configurado con el mismo nonce de 8 bytes
    + contador de 8 bytes.

    La librería acepta un nonce completo de 16 bytes.
    Lo construimos igual que en el manual: nonce_8 || counter.
    """
    full_nonce = nonce_8 + initial_counter.to_bytes(COUNTER_BYTES, "big")
    cipher     = Cipher(algorithms.AES(key), modes.CTR(full_nonce),
                        backend=default_backend())
    enc        = cipher.encryptor()
    return enc.update(data) + enc.finalize()


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────

def test_ctr(description: str, plaintext: bytes,
             key: bytes, nonce: bytes,
             initial_counter: int = 0) -> None:
    print(f"\n  [{description}]")
    print(f"    Plaintext   : {plaintext!r}")
    print(f"    Nonce (8B)  : {nonce.hex()}")
    print(f"    Counter ini : {initial_counter}")

    # Cifrado manual
    ct_manual = aes_ctr_manual(plaintext, key, nonce, initial_counter)
    # Cifrado con librería
    ct_lib    = aes_ctr_lib(plaintext, key, nonce, initial_counter)

    print(f"    CT manual   : {ct_manual.hex()}")
    print(f"    CT librería : {ct_lib.hex()}")

    match = "✔" if ct_manual == ct_lib else "✘"
    print(f"    Coinciden   : {match}")
    assert ct_manual == ct_lib, \
        f"FALLO en '{description}': manual ≠ librería"

    # Descifrado manual
    pt_recovered = aes_ctr_manual(ct_manual, key, nonce, initial_counter)
    assert pt_recovered == plaintext, \
        f"FALLO en descifrado de '{description}'"
    print(f"    Descifrado  : {pt_recovered!r}  ✔")


if __name__ == "__main__":
    print("=" * 65)
    print("EJERCICIO 8 – AES-CTR manual (nonce 8B || counter 8B)")
    print("=" * 65)

    key   = os.urandom(16)
    nonce = os.urandom(NONCE_BYTES)

    test_ctr("Mensaje corto (< 1 bloque)",
             b"Hola CTR manual", key, nonce)

    test_ctr("Exactamente 1 bloque (16 bytes)",
             b"1234567890abcdef", key, nonce)

    test_ctr("2 bloques exactos (32 bytes)",
             b"A" * 32,          key, nonce)

    test_ctr("Mensaje de longitud arbitraria (no múltiplo de 16)",
             b"CTR no necesita padding para funcionar correctamente!",
             key, nonce)

    test_ctr("Mensaje vacío",
             b"",                key, nonce)

    test_ctr("Un solo byte",
             b"Z",               key, nonce)

    test_ctr("Contador inicial != 0",
             b"Inicio en counter=100",
             key, nonce, initial_counter=100)

    # ── Demostración visual del keystream ─────────────────
    print("\n─" * 33)
    print("  Keystream generado bloque a bloque (AES-ECB del counter)")
    print("─" * 33)
    demo_key   = b"\x00" * 16
    demo_nonce = b"\x00" * 8
    for i in range(3):
        cb  = _build_counter_block(demo_nonce, i)
        ks  = aes_enc_block(cb, demo_key)
        print(f"  Block {i}: counter_block={cb.hex()} → keystream={ks.hex()}")

    print("\n✔  Todos los tests del Ejercicio 8 superados.")
    print("   CTR manual produce resultados IDÉNTICOS a la librería.\n")