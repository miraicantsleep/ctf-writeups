#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall'
elf = context.binary = ELF(exe, checksec=True)
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
breakrva 0x15b2
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================
'''
 ---------------------------------
| Symphonie der Entschlossenheit  |
 ---------------------------------
'''
def setRounds(round):
    # 4 rounds -> 8 bytes output
    # 7 rounds -> 12 bytes output
    # 10 rounds -> 16 bytes output
    
    io.sendlineafter(b':', b'1')
    io.sendlineafter(b':', str(round).encode())

def setPlaintext(plaintext):
    io.sendlineafter(b':', b'2')
    io.sendlineafter(b':', f'{plaintext}'.encode())
    
def encryptData() -> int:
    io.sendlineafter(b':', b'3')
    io.recvuntil(b'Encrypted: ')
    return int(io.recvline().strip(), 16)

def reset():
    io.sendlineafter(b':', b'4')
    
def exitt():
    io.sendlineafter(b':', b'5')
    
    
# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    setPlaintext(b'')
    

    io.interactive()
    
if __name__ == '__main__':
    exploit()