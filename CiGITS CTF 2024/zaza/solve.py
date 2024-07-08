from pwn import *
host = '139.59.120.240'
port = 13131

io = remote(host, port)

io.sendline(b'4919')
io.sendline(b'86628383')

key = "anextremelycomplicatedkeythatisdefinitelyuselessss"
decoded = xor("2& =$!-( <*+*( ?!&$$6,. )\' $19 , #9=!1 <*=6 <6;66#", key)
print(decoded)

io.sendline(decoded)
io.interactive()