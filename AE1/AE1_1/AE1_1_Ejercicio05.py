def xor_binario(a, b):
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))


def xor_hex(a, b):
    return hex(int(a, 16) ^ int(b, 16))


if __name__ == "__main__":
    print(xor_binario("0011", "1100"))  # 1111
    print(xor_hex("a4", "93"))          # 0x37
