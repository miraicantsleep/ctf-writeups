from pwn import *

io = remote('titan.picoctf.net', 51798)

io.recvuntil(b'Word: ')
word = io.recvline().strip().decode()

payload = []
for char in word:
    payload.append(hex(ord(char))[2:])

payload_little_endian = ''.join(payload[::-1]).encode()
io.sendline(payload_little_endian)

payload_big_endian = ''.join(payload).encode()
io.sendline(payload_big_endian)

io.interactive()
