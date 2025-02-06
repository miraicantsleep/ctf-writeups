This project includes two key scripts: start.sh and boot.sh.

The start.sh script compiles the exploit.c file, which is a boilerplate exploit provided for you to modify or use as a starting point. Once compiled, the exploit is placed inside the initramfs file system. After preparing the environment, start.sh automatically triggers boot.sh.

The boot.sh script is responsible for booting the kernel with the initramfs that includes the compiled exploit. This gives you a local environment to test and run your exploit.

If you're working remotely, you can transfer the compiled exploit using base64. First, encode the exploit using base64, transfer it to the remote system, then decode it back into the original executable format. Once decoded, you can run the exploit on the remote machine.