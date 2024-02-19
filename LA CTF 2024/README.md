# LA CTF 2024
I took part in this CTF solo as miraimiraimirai

## Challenges
| Name | Category | Description | Solve |
| :---: |  :---: |  :---: | :---: |
| aplet123 | pwn | Leaking values off the stack, 4 bits at a time to leak canary then calls win function | ✅ |
| 52-card-monty | pwn | Leaking values off the stack via out-of-bounds array reading to get canary and ELF base, then calls win function | ✅ |
| sus | pwn | Controlling rdi by overflowing the buffer, leaking libc function to call system("/bin/sh") | ✅ |
| pizza | pwn | printf vulnerability to leak and write values off and to the stack | solved after ctf |