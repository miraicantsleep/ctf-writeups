def to_identity_map_inverse(a):
    return chr((a % 26) + 0x41)

def from_identity_map_inverse(a):
    return a + 0x41

def decrypt(c):
    m = ''
    for i in range(len(c)):
        ch = c[i]
        if not ch.isalpha():
            dch = ch
        else:
            dchi = to_identity_map_inverse(from_identity_map_inverse(ord(ch)) - i)
            dch = dchi
        m += dch
    return m

with open('output.txt', 'r') as f:
    encrypted_flag = f.read().split('\n')[1].strip()

decrypted_flag = decrypt(encrypted_flag)

print('HTB{' + decrypted_flag + '}')
 
