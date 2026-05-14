import hashlib
 
mensajes = ["Hola", "hola", "Hola ", "Hola1"]
 
print(f"{'Mensaje':<12} {'SHA-256 (hex)'}")
print("-" * 76)
for m in mensajes:
    h = hashlib.sha256(m.encode()).hexdigest()
    print(f"{repr(m):<12} {h}")