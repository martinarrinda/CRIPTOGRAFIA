import hmac
import hashlib

clave = input("Introduce la clave secreta: ")
mensaje = input("Introduce el mensaje: ")

mac = hmac.new(clave.encode(), mensaje.encode(), hashlib.sha256)
print(f"\nHMAC-SHA256: {mac.hexdigest()}")