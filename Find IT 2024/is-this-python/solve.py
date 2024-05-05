key = 'findit' + '2024'
flag_enc = [32, 0, 0, 0, 32, 32, 113, 100, 116, 79, 4, 89, 2, 80, 54, 66, 83, 92, 3, 107, 8, 80, 9, 11, 54, 16, 93, 1, 83, 90, 82, 7, 49, 80, 80, 71, 10, 1, 1, 73]  # 
key_arr = [ord(char) for char in key]

key_arr = (key_arr * ((len(flag_enc) // len(key_arr)) + 1))[:len(flag_enc)]

flag_dec = [chr(enc ^ k) for enc, k in zip(flag_enc, key_arr)]

flag_dec_text = ''.join(flag_dec)

print("Decrypted Text:", flag_dec_text)