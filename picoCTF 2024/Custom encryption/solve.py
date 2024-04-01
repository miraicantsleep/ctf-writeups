def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generator(g, x, p):
    return pow(g, x, p)



def decrypt(cipher, shared_key, text_key, p, g):
    plain_text = ""
    key_length = len(text_key)
    for i, char in enumerate(cipher):
        decrypted_char = chr(char // shared_key)
        key_char = text_key[i % key_length]
        plain_text += chr(ord(decrypted_char) ^ ord(key_char))
    return plain_text[::-1]


def reverse_test(cipher, text_key, shared_key, p, g):
    if not is_prime(p) or not is_prime(g):
        print("Enter prime numbers")
        return
    semi_cipher = decrypt(cipher, shared_key, text_key, p, g)
    print(f'Semi-cipher text is: {semi_cipher}')
    u = generator(g, 1, p)
    v = generator(g, 1, p)
    a = 1
    b = 1
    while generator(u, a, p) != shared_key:
        a += 1
    while generator(v, b, p) != shared_key:
        b += 1
    print(f"a = {a}")
    print(f"b = {b}")
    plain_text = dynamic_xor_encrypt(semi_cipher, text_key)
    print(f'Plain text is: {plain_text}')


if __name__ == "__main__":
    cipher = [260307, 491691, 491691, 2487378, 2516301, 0, 1966764, 1879995, 1995687, 1214766, 0, 2400609, 607383, 144615, 1966764, 0, 636306, 2487378, 28923, 1793226, 694152, 780921, 173538, 173538, 491691, 173538, 751998, 1475073, 925536, 1417227, 751998, 202461, 347076, 491691]
    shared_key = 281857
    p = 97
    g = 31
    text_key = "trudeau"
    reverse_test(cipher, text_key, shared_key, p, g)
