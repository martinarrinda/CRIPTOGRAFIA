import hashlib

mensaje = input("Introduce un mensaje: ")
hash_resultado = hashlib.sha256(mensaje.encode()).hexdigest()
print(f"SHA-256: {hash_resultado}")