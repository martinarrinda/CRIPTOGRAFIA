import secrets
from Crypto.Cipher import Salsa20   # pycryptodome
import nacl.secret                   # pynacl  (libsodium)
import nacl.utils


# ─── SALSA20 ──────────────────────────────────────────────────────

def salsa20_cifrar(mensaje: bytes, clave: bytes) -> tuple[bytes, bytes]:
    """Cifra con Salsa20 usando pycryptodome.
    Devuelve (cifrado, nonce).  Clave: 16 o 32 bytes."""
    cipher = Salsa20.new(key=clave)
    cifrado = cipher.encrypt(mensaje)
    return cifrado, cipher.nonce  # nonce: 8 bytes generado automáticamente


def salsa20_descifrar(cifrado: bytes, clave: bytes, nonce: bytes) -> bytes:
    """Descifra con Salsa20 usando pycryptodome (distinta instancia)."""
    cipher = Salsa20.new(key=clave, nonce=nonce)
    return cipher.decrypt(cifrado)


# ─── XSALSA20 ─────────────────────────────────────────────────────

def xsalsa20_cifrar(mensaje: bytes, clave: bytes) -> bytes:
    """Cifra con XSalsa20-Poly1305 usando pynacl (SecretBox).
    Devuelve el mensaje cifrado con nonce y MAC integrados."""
    box = nacl.secret.SecretBox(clave)
    return box.encrypt(mensaje)          # nonce aleatorio interno + MAC


def xsalsa20_descifrar(cifrado: bytes, clave: bytes) -> bytes:
    """Descifra con XSalsa20-Poly1305 usando pynacl."""
    box = nacl.secret.SecretBox(clave)
    return box.decrypt(cifrado)


# ─── Demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  EJERCICIO 2 – Salsa20 y XSalsa20")
    print("=" * 55)

    # ── Salsa20 ──────────────────────────────────────────────────
    print("\n── Salsa20 ──")
    clave_salsa = secrets.token_bytes(32)           # 256 bits
    mensaje_s   = b"Mensaje secreto con Salsa20"

    cifrado_s, nonce_s = salsa20_cifrar(mensaje_s, clave_salsa)
    descifrado_s       = salsa20_descifrar(cifrado_s, clave_salsa, nonce_s)

    print(f"Mensaje original : {mensaje_s.decode()}")
    print(f"Clave (hex)      : {clave_salsa.hex()}")
    print(f"Nonce (hex)      : {nonce_s.hex()}")
    print(f"Cifrado (hex)    : {cifrado_s.hex()}")
    print(f"Descifrado       : {descifrado_s.decode()}")
    print(f"Correcto         : {mensaje_s == descifrado_s}")

    # ── XSalsa20 ─────────────────────────────────────────────────
    print("\n── XSalsa20 (SecretBox = XSalsa20 + Poly1305) ──")
    clave_xs  = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)  # 32 bytes
    mensaje_x = b"Mensaje secreto con XSalsa20"

    # Cifrar con pynacl
    cifrado_x = xsalsa20_cifrar(mensaje_x, clave_xs)

    # Descifrar con pynacl (la librería gestiona nonce y MAC internamente)
    descifrado_x = xsalsa20_descifrar(cifrado_x, clave_xs)

    print(f"Mensaje original : {mensaje_x.decode()}")
    print(f"Clave (hex)      : {clave_xs.hex()}")
    print(f"Cifrado (hex)    : {cifrado_x.hex()}")
    print(f"Descifrado       : {descifrado_x.decode()}")
    print(f"Correcto         : {mensaje_x == descifrado_x}")

    # ── Diferencias clave ─────────────────────────────────────────
    print("\n── Diferencias Salsa20 vs XSalsa20 ──")
    print(f"  Nonce Salsa20  : {len(nonce_s) * 8} bits ({len(nonce_s)} bytes)")
    xs_nonce_len = nacl.secret.SecretBox.NONCE_SIZE
    print(f"  Nonce XSalsa20 : {xs_nonce_len * 8} bits ({xs_nonce_len} bytes) → más seguro")
    print("  XSalsa20 incluye autenticación (MAC) integrada → SecretBox")