import secrets
import struct
from Crypto.Cipher import ChaCha20                              # pycryptodome
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms  # cryptography


# ─── Funciones ────────────────────────────────────────────────────

def chacha20_cifrar(mensaje: bytes, clave: bytes, nonce: bytes) -> bytes:
    """Cifra con ChaCha20 usando pycryptodome.
    Clave: 32 bytes. Nonce: 12 bytes (formato IETF / RFC 8439)."""
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    return cipher.encrypt(mensaje)


def chacha20_descifrar(cifrado: bytes, clave: bytes, nonce: bytes) -> bytes:
    """Descifra con ChaCha20 usando la librería `cryptography` (hazmat).

    Adaptación de nonce:
      pycryptodome  → nonce  12 bytes (RFC 8439)
      cryptography  → nonce  16 bytes = counter 4B (LE) + nonce 12B
    """
    nonce_16 = struct.pack("<I", 0) + nonce   # counter=0 + nonce 12 bytes
    algorithm = algorithms.ChaCha20(key=clave, nonce=nonce_16)
    cipher    = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(cifrado)


# ─── Demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  EJERCICIO 3 – ChaCha20")
    print("=" * 55)

    clave   = secrets.token_bytes(32)   # 256 bits
    nonce   = secrets.token_bytes(12)   # 96 bits  (IETF RFC 8439)
    mensaje = b"Mensaje secreto con ChaCha20"

    # Cifrar con pycryptodome
    cifrado    = chacha20_cifrar(mensaje, clave, nonce)

    # Descifrar con cryptography
    descifrado = chacha20_descifrar(cifrado, clave, nonce)

    print(f"Mensaje original : {mensaje.decode()}")
    print(f"Clave (hex)      : {clave.hex()}")
    print(f"Nonce (hex)      : {nonce.hex()}  ({len(nonce)*8} bits)")
    print(f"Cifrado (hex)    : {cifrado.hex()}")
    print(f"Descifrado       : {descifrado.decode()}")
    print(f"Correcto         : {mensaje == descifrado}")

    print("\n── Nota de compatibilidad ──")
    print("  pycryptodome  → nonce  12 bytes (RFC 8439)")
    print("  cryptography  → nonce  16 bytes (counter 4B LE + nonce 12B)")
    print("  Solución: struct.pack('<I', 0) + nonce_12")

    # ── Variante: cifrar con cryptography y descifrar con pycryptodome ──
    print("\n── Variante inversa: cifrar con cryptography, descifrar con pycryptodome ──")
    nonce2   = secrets.token_bytes(12)
    nonce2_16 = struct.pack("<I", 0) + nonce2

    # Cifrar con cryptography
    algorithm2 = algorithms.ChaCha20(key=clave, nonce=nonce2_16)
    cipher2    = Cipher(algorithm2, mode=None)
    encryptor2 = cipher2.encryptor()
    cifrado2   = encryptor2.update(mensaje)

    # Descifrar con pycryptodome
    cipher2_dec = ChaCha20.new(key=clave, nonce=nonce2)
    descifrado2 = cipher2_dec.decrypt(cifrado2)

    print(f"Cifrado (hex)  : {cifrado2.hex()}")
    print(f"Descifrado     : {descifrado2.decode()}")
    print(f"Correcto       : {mensaje == descifrado2}")