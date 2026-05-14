import hmac
import hashlib
 
def calcular_hmac(clave, mensaje):
    return hmac.new(clave.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
 
def verificar_hmac(clave, mensaje, hmac_recibido):
    hmac_calculado = calcular_hmac(clave, mensaje)
    return hmac.compare_digest(hmac_calculado, hmac_recibido), hmac_calculado
 
CLAVE_COMPARTIDA = "clave_secreta_compartida"
 
mensaje_original = "Transferir 100 euros"
hmac_original = calcular_hmac(CLAVE_COMPARTIDA, mensaje_original)
 
print("=" * 55)
print("  Simulación de modificación maliciosa")
print("=" * 55)
print(f"\n[Alice] Mensaje original  : {mensaje_original}")
print(f"[Alice] HMAC calculado    : {hmac_original}")
 
mensaje_modificado = "Transferir 1000 euros"
 
print(f"\n[Atacante] Mensaje modificado: {mensaje_modificado}")
print(f"[Atacante] HMAC enviado      : {hmac_original}  (el mismo, sin clave no puede recalcularlo)")
 
print("\n  ... mensaje modificado llega a Bob ...\n")
 
valido, hmac_recalculado = verificar_hmac(CLAVE_COMPARTIDA, mensaje_modificado, hmac_original)
 
print(f"[Bob] Mensaje recibido    : {mensaje_modificado}")
print(f"[Bob] HMAC recibido       : {hmac_original}")
print(f"[Bob] HMAC recalculado    : {hmac_recalculado}")
print(f"[Bob] Verificación HMAC   : {'VÁLIDO' if valido else 'INVÁLIDO - modificación detectada'}")