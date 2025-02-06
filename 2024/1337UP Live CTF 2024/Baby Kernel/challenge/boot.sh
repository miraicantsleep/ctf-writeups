#!/bin/bash

qemu-system-x86_64 \
    -m 64M \
    -kernel "/mnt/d/ctf-writeups/1337UP Live CTF 2024/Baby Kernel/challenge/bzImage" \
    -initrd "/mnt/d/ctf-writeups/1337UP Live CTF 2024/Baby Kernel/challenge/initramfs.cpio.gz" \
    -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
    -nographic \
    -no-reboot \
    -monitor /dev/null
