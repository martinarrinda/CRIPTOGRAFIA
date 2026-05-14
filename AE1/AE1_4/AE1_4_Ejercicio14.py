import hmac
import hashlib

def calcular_hmac(clave, mensaje):
    return hmac.new(clave.encode(), mensaje.encode(), hashlib.sha256).hexdigest()

def verificar_hmac(clave, mensaje, hmac_recibido):
    hmac_calculado = calcular_hmac(clave, mensaje)
    return hmac.compare_digest(hmac_calculado, hmac_recibido), hmac_calculado

CLAVE_COMPARTIDA = "clave_secreta_compartida"

print("=" * 50)
print("  Simulación de comunicación Alice -> Bob")
print("=" * 50)

mensaje_alice = "Hola Bob, el pago es de 500 euros."
hmac_alice = calcular_hmac(CLAVE_COMPARTIDA, mensaje_alice)

print(f"\n[Alice] Mensaje enviado : {mensaje_alice}")
print(f"[Alice] HMAC generado  : {hmac_alice}")

print("\n  ... mensaje en tránsito ...\n")

mensaje_bob = mensaje_alice
hmac_bob = hmac_alice

valido, hmac_recalculado = verificar_hmac(CLAVE_COMPARTIDA, mensaje_bob, hmac_bob)

print(f"[Bob] Mensaje recibido      : {mensaje_bob}")
print(f"[Bob] HMAC recibido         : {hmac_bob}")
print(f"[Bob] HMAC recalculado      : {hmac_recalculado}")
print(f"[Bob] Verificación HMAC     : {'VÁLIDO - mensaje auténtico e íntegro' if valido else 'INVÁLIDO - mensaje comprometido'}")