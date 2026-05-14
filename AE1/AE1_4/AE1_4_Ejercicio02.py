import hashlib
 
mensaje = input("Introduce un mensaje: ")
datos = mensaje.encode()
 
algoritmos = {
    "MD5":     hashlib.md5(datos).hexdigest(),
    "SHA-1":   hashlib.sha1(datos).hexdigest(),
    "SHA-256": hashlib.sha256(datos).hexdigest(),
    "SHA-512": hashlib.sha512(datos).hexdigest(),
}
 
print()
for nombre, valor in algoritmos.items():
    print(f"{nombre:>8} ({len(valor) * 4} bits / {len(valor)} hex): {valor}")