import hashlib
import hmac
 
CLAVE = "mi_clave_secreta"
mensaje = input("Introduce un mensaje: ")
 
hash_normal = hashlib.sha256(mensaje.encode()).hexdigest()
hmac_resultado = hmac.new(CLAVE.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
 
print(f"\nMensaje        : {mensaje}")
print(f"Clave HMAC     : {CLAVE}")
print(f"\nSHA-256 normal : {hash_normal}")
print(f"HMAC-SHA256    : {hmac_resultado}")
 
mensaje_mod = mensaje + "X"
hash_mod = hashlib.sha256(mensaje_mod.encode()).hexdigest()
hmac_mod = hmac.new(CLAVE.encode(), mensaje_mod.encode(), hashlib.sha256).hexdigest()
 
clave_mod = "otra_clave_distinta"
hmac_clave_mod = hmac.new(clave_mod.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
 
print(f"\n--- Efecto de modificar el mensaje (añadimos 'X') ---")
print(f"SHA-256 modificado : {hash_mod}")
print(f"HMAC modificado    : {hmac_mod}")
 
print(f"\n--- Efecto de modificar la clave ---")
print(f"HMAC clave '{clave_mod}': {hmac_clave_mod}")