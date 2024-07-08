from pwn import *

host = 'ctf.mf.grsu.by'
port = 9006
context.log_level = 'info'

mapping = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '+': 't',
    '!': 'i',
    '+': 't'
}

def decode(s):
    for k, v in mapping.items():
        s = s.replace(k, v)
    return s

io = remote(host, port)

for _ in range(50):
    io.recvuntil(b'/50\n')
    s = io.recvline().decode().strip()
    io.sendline(decode(s))

io.interactive()
io.close()