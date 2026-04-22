
def detect_ecb(ciphertext_hex: str) -> tuple[bool, int]:
    """
    Recibe un ciphertext en hexadecimal.
    Devuelve (es_ECB, número_de_bloques_repetidos).
    Un bloque repetido = (total_bloques - bloques_únicos).
    """
    raw = bytes.fromhex(ciphertext_hex)
    block_size = 16  # AES siempre usa bloques de 128 bits = 16 bytes

    # Dividir en bloques de 16 bytes
    blocks = [raw[i:i + block_size] for i in range(0, len(raw), block_size)]

    total_blocks  = len(blocks)
    unique_blocks = len(set(blocks))
    repeated      = total_blocks - unique_blocks

    return repeated > 0, repeated


def find_ecb_candidates(ciphertext_list: list[str]) -> None:
    """
    Analiza una lista de ciphertexts (hex) e imprime cuáles
    podrían haber sido cifrados con AES-ECB.
    """
    best_idx      = -1
    best_repeated = 0

    print("=" * 55)
    print("ANÁLISIS DE POSIBLE USO DE AES-ECB")
    print("=" * 55)

    for idx, ct_hex in enumerate(ciphertext_list):
        is_ecb, repeated = detect_ecb(ct_hex)
        if is_ecb:
            print(f"  ► Posible ECB: índice {idx}  |  "
                  f"{repeated} bloque(s) repetido(s)")
            if repeated > best_repeated:
                best_repeated = repeated
                best_idx      = idx

    if best_idx >= 0:
        print(f"\n  ✔  El candidato más probable a ECB es el índice: {best_idx}")
    else:
        print("  ✘  No se detectaron ciphertexts con bloques repetidos.")
    print("=" * 55)


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":

    # ── Test 1: ejemplo del enunciado ──────────────────────
    print("\n[Test 1] Ejemplo del enunciado")
    lista = [
        "6bc1bee22e409f96e93d7e117393172a",
        # 2 bloques de 16 bytes IGUALES → ECB fingerprint
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff",
        "aabbccddeeff00112233445566778899",
    ]
    find_ecb_candidates(lista)

    # ── Test 2: tres bloques repetidos ─────────────────────
    print("\n[Test 2] Tres bloques repetidos")
    bloque_repetido = "deadbeefcafebabe0123456789abcdef"
    lista2 = [
        "aabbccddeeff00112233445566778899",
        bloque_repetido * 3,                    # ← 3 copias idénticas
        "00112233445566778899aabbccddeeff",
    ]
    find_ecb_candidates(lista2)

    # ── Test 3: ningún ECB ─────────────────────────────────
    print("\n[Test 3] Sin bloques repetidos (ningún ECB)")
    lista3 = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
    ]
    find_ecb_candidates(lista3)

    # ── Test 4: ciphertext real AES-ECB ────────────────────
    # Generamos uno a mano para verificar
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os

    print("\n[Test 4] Ciphertext real cifrado con AES-ECB")
    key       = os.urandom(16)
    plaintext = b"A" * 16 + b"B" * 16 + b"A" * 16   # 1º y 3º bloque iguales

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct_real   = encryptor.update(plaintext) + encryptor.finalize()

    ct_hex = ct_real.hex()
    print(f"  Ciphertext (hex): {ct_hex}")
    is_ecb, reps = detect_ecb(ct_hex)
    print(f"  ¿Detectado como ECB? {is_ecb}  |  Bloques repetidos: {reps}")
    assert is_ecb,   "ERROR: debería detectarse como ECB"
    assert reps == 1, f"ERROR: se esperaba 1 repetición, hay {reps}"
    print("  ✔  Test 4 superado")