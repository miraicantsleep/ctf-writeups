from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b

class Cipher:
    def __init__(self, key):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i + self.BLOCK_SIZE // 16]) for i in range(0, len(key), self.BLOCK_SIZE // 16)]
        self.DELTA = 0x9e3779b9

    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def decrypt(self, ct):
        blocks = [ct[i:i + self.BLOCK_SIZE // 8] for i in range(0, len(ct), self.BLOCK_SIZE // 8)]

        pt = b''
        for block in blocks:
            pt += self.decrypt_block(block)

        return pt.rstrip(b'\x00')

    def decrypt_block(self, ct):
        c0 = b2l(ct[:4])
        c1 = b2l(ct[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE // 2)) - 1

        s = self.DELTA * 32
        for i in range(32):
            c1 -= ((c0 << 4) + K[2]) ^ (c0 + s) ^ ((c0 >> 5) + K[3])
            c1 &= msk
            c0 -= ((c1 << 4) + K[0]) ^ (c1 + s) ^ ((c1 >> 5) + K[1])
            c0 &= msk
            s -= self.DELTA

        m = ((c0 << (self.BLOCK_SIZE // 2)) + c1) & ((1 << self.BLOCK_SIZE) - 1)

        return l2b(m)

if __name__ == '__main__':
    key_hex = "850c1413787c389e0b34437a6828a1b2"
    ciphertext_hex = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"

    # Convert hexadecimal strings to bytes
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Decrypt the ciphertext
    cipher = Cipher(key)
    decrypted_message = cipher.decrypt(ciphertext)

    print(decrypted_message.decode())
 
