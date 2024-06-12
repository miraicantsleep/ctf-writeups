#!/usr/bin/python3
from pwn import *
from ctypes import CDLL
import time

# =========================================================
#                          SETUP                         
# =========================================================
exe = './paranoia' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = CDLL('/usr/lib/libc.so.6')
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '20.80.240.190', 1234 # <-- change this

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
#                         NOTES
# =========================================================




# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    libc.srand(libc.time(None))
    
    leak = io.recvline().strip().decode().split()
    print(leak)
    
    for item in leak:
        random = libc.rand() % 256
        print(chr(int(item) ^ random), end='')
    
if __name__ == '__main__':
    exploit()