import secrets


# ─── Funciones ────────────────────────────────────────────────────

def otp_cifrar(mensaje: str) -> tuple[bytes, bytes]:
    """Cifra un mensaje con OTP. Devuelve (cifrado, clave)."""
    msg_bytes = mensaje.encode("utf-8")

    # Paso 1: clave aleatoria del mismo tamaño que el mensaje
    clave = secrets.token_bytes(len(msg_bytes))

    # Paso 2: XOR byte a byte (sin padding necesario, misma longitud)
    cifrado = bytes(m ^ c for m, c in zip(msg_bytes, clave))

    return cifrado, clave


def otp_descifrar(cifrado: bytes, clave: bytes) -> str:
    """Descifra un mensaje OTP aplicando XOR con la misma clave."""
    msg_bytes = bytes(c ^ k for c, k in zip(cifrado, clave))
    return msg_bytes.decode("utf-8")


# ─── Demo ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mensaje_original = "Hola Mundo Secreto 🔐"

    print("=" * 55)
    print("  EJERCICIO 1 – One-Time Pad (OTP)")
    print("=" * 55)

    cifrado, clave = otp_cifrar(mensaje_original)
    descifrado     = otp_descifrar(cifrado, clave)

    print(f"Mensaje original : {mensaje_original}")
    print(f"Clave (hex)      : {clave.hex()}")
    print(f"Cifrado (hex)    : {cifrado.hex()}")
    print(f"Descifrado       : {descifrado}")
    print(f"Correcto         : {mensaje_original == descifrado}")
    print()

    # ── Demostración de seguridad: reutilizar clave revela info ──
    print("── Demo reutilización de clave (INSEGURO) ──")
    m1 = "Texto secreto A!!"
    m2 = "Texto secreto B!!"
    c1, k = otp_cifrar(m1)
    c2    = bytes(b ^ ck for b, ck in zip(m2.encode(), k))  # misma clave

    xor_cifrados = bytes(a ^ b for a, b in zip(c1, c2))
    xor_mensajes = bytes(a ^ b for a, b in zip(m1.encode(), m2.encode()))
    print(f"  C1 XOR C2 = {xor_cifrados.hex()}")
    print(f"  M1 XOR M2 = {xor_mensajes.hex()}")
    print(f"  ¡Son iguales! La clave se cancela → la reutilización es PELIGROSA.")