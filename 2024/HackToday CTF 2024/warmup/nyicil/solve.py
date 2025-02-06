from pwn import *
elf = ELF("./Nyicil")
io = process(elf.path)
flag = b'hacktoday{'
context.log_level = 'info'

while True:
    found = False
    for tryChar in string.printable:
        test_flag = flag + tryChar.encode()
        io.sendline(test_flag)
        response = io.recvuntil(b'!')
        if b'BENAR' in response and b'ADA YANG BENAR' not in response:
            flag = test_flag
            print(f"Flag: {flag}")
            if tryChar == '}':
                found = True
            break
    if found:
        io.close()
        break
    elif not found and tryChar == '}':
        print("Failed to find the correct character.")
        break

io.interactive()
