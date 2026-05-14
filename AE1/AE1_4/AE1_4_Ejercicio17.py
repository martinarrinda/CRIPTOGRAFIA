import hashlib
import hmac
 
CLAVE = "clave_cifrado_autenticado"
mensaje = input("Introduce un mensaje a proteger: ")
 
hash_normal = hashlib.sha256(mensaje.encode()).hexdigest()
hmac_resultado = hmac.new(CLAVE.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
 
print(f"\nMensaje        : {mensaje}")
print(f"Clave HMAC     : {CLAVE}")
print(f"\nSHA-256 normal : {hash_normal}")
print(f"HMAC-SHA256    : {hmac_resultado}")
 
mensaje_alt = "mensaje completamente distinto"
hash_alt = hashlib.sha256(mensaje_alt.encode()).hexdigest()
hmac_alt = hmac.new(CLAVE.encode(), mensaje_alt.encode(), hashlib.sha256).hexdigest()
 
clave_alt = "clave_diferente_123"
hmac_clave_alt = hmac.new(clave_alt.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
 
print(f"\n--- Con mensaje alternativo: '{mensaje_alt}' ---")
print(f"SHA-256           : {hash_alt}")
print(f"HMAC-SHA256       : {hmac_alt}")
 
print(f"\n--- Mismo mensaje, clave diferente: '{clave_alt}' ---")
print(f"HMAC-SHA256       : {hmac_clave_alt}")