import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE  = 16
NONCE_SIZE  = 8   # 8 bytes de nonce


# ─────────────────────────────────────────────────────────
# PKCS7 (autocontenido)
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
# AES-ECB helpers
# ─────────────────────────────────────────────────────────

def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """Cifra data (ya con padding) con AES-ECB."""
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Descifra data con AES-ECB."""
    cipher    = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


# ─────────────────────────────────────────────────────────
# Clase Participante (Alicia / Bob comparten la misma lógica)
# ─────────────────────────────────────────────────────────

class Participant:
    """
    Simula un participante en el protocolo AES-ECB con nonce.

    nonce_value : el nonce actual (entero de 8 bytes).
    is_initiator: si True, genera el nonce inicial y lo envía.
    """

    def __init__(self, name: str, key: bytes,
                 is_initiator: bool = False,
                 initial_nonce: int | None = None):
        self.name         = name
        self.key          = key
        self.is_initiator = is_initiator

        if is_initiator:
            # El iniciador escoge el nonce
            raw = os.urandom(NONCE_SIZE)
            self.nonce = int.from_bytes(raw, "big")
        else:
            # El receptor lo recibirá en el primer mensaje
            self.nonce = initial_nonce if initial_nonce is not None else 0

        self.msg_count = 0  # nº de mensajes enviados/recibidos

    def _current_nonce_bytes(self) -> bytes:
        return self.nonce.to_bytes(NONCE_SIZE, "big")

    def _increment_nonce(self) -> None:
        self.nonce = (self.nonce + 1) & ((1 << 64) - 1)  # mod 2^64

    # ── Envío ─────────────────────────────────────────────

    def send(self, plaintext: bytes) -> bytes:
        """
        Construye el paquete a enviar.
        Formato primer mensaje : nonce (8 bytes) || ciphertext
        Formato siguientes     : ciphertext
        El plaintext incluye siempre el nonce actual como prefijo
        para que ECB no revele patrones.
        """
        nonce_bytes = self._current_nonce_bytes()

        # Prefijamos el nonce al plaintext (protección ECB)
        payload = nonce_bytes + plaintext
        padded  = pkcs7_pad(payload)
        ct      = aes_ecb_encrypt(padded, self.key)

        is_first = (self.msg_count == 0)
        self._increment_nonce()
        self.msg_count += 1

        if is_first:
            # El primer paquete lleva el nonce en claro para sincronización
            packet = nonce_bytes + ct
            print(f"  [{self.name}→] MSG #{self.msg_count} "
                  f"(con nonce en claro) | nonce={nonce_bytes.hex()} "
                  f"| CT={ct.hex()}")
        else:
            packet = ct
            print(f"  [{self.name}→] MSG #{self.msg_count} "
                  f"| nonce interno={nonce_bytes.hex()} "
                  f"| CT={ct.hex()}")

        return packet

    # ── Recepción ─────────────────────────────────────────

    def receive(self, packet: bytes, is_first: bool = False) -> bytes:
        """
        Descifra el paquete entrante.
        Si es el primer mensaje, extrae el nonce de los primeros 8 bytes.
        """
        if is_first:
            # Extraer y sincronizar nonce
            nonce_bytes = packet[:NONCE_SIZE]
            self.nonce  = int.from_bytes(nonce_bytes, "big")
            ct          = packet[NONCE_SIZE:]
        else:
            ct = packet

        padded_payload = aes_ecb_decrypt(ct, self.key)
        payload        = pkcs7_unpad(padded_payload)

        # Los primeros 8 bytes son el nonce incluido en el plaintext
        recv_nonce   = payload[:NONCE_SIZE]
        plaintext    = payload[NONCE_SIZE:]

        # Verificar que el nonce coincide con el esperado
        expected_nonce = self._current_nonce_bytes()
        if recv_nonce != expected_nonce:
            raise ValueError(
                f"[{self.name}] Nonce inválido: "
                f"recibido={recv_nonce.hex()} "
                f"esperado={expected_nonce.hex()}"
            )

        self._increment_nonce()
        self.msg_count += 1
        print(f"  [{self.name}←] MSG #{self.msg_count} recibido OK "
              f"| nonce={recv_nonce.hex()} | PT={plaintext!r}")
        return plaintext


# ─────────────────────────────────────────────────────────
# SIMULACIÓN
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("EJERCICIO 6 – Protocolo AES-ECB con Nonce")
    print("=" * 60)

    # Clave compartida (negociada de antemano por otro canal)
    shared_key = os.urandom(16)
    print(f"\n  Clave compartida (hex): {shared_key.hex()}\n")

    # ── Crear participantes ───────────────────────────────
    alice = Participant("Alicia", shared_key, is_initiator=True)
    bob   = Participant("Bob",    shared_key, is_initiator=False)

    mensajes = [
        b"Hola Bob, soy Alicia!",
        b"Este es el segundo mensaje",
        b"Mensaje 3: mismo texto que antes",
        b"Este es el segundo mensaje",    # repetido → CT diferente por nonce
    ]

    print("─" * 60)
    print("  Conversación Alicia → Bob")
    print("─" * 60)

    for i, msg in enumerate(mensajes):
        is_first = (i == 0)
        paquete  = alice.send(msg)
        recv_msg = bob.receive(paquete, is_first=is_first)
        assert recv_msg == msg, f"Error en mensaje {i+1}: {recv_msg!r} ≠ {msg!r}"
        print()

    # ── Verificar que mensajes iguales tienen CT diferente ─
    print("─" * 60)
    print("  Comprobación: mismo PT → CTs distintos por nonce")
    print("─" * 60)
    alice2 = Participant("Alicia2", shared_key, is_initiator=True)
    bob2   = Participant("Bob2",    shared_key, is_initiator=False)

    repeat_msg = b"Mensaje repetido exacto"
    p1 = alice2.send(repeat_msg)
    p2 = alice2.send(repeat_msg)

    ct1 = p1[NONCE_SIZE:]   # quitar nonce en claro del primer paquete
    ct2 = p2

    print(f"\n  CT mensaje 1: {ct1.hex()}")
    print(f"  CT mensaje 2: {ct2.hex()}")
    assert ct1 != ct2, "ERROR: los CTs son iguales (¡el nonce no funciona!)"
    print("  ✔  Los ciphertexts son DISTINTOS pese al mismo plaintext.\n")