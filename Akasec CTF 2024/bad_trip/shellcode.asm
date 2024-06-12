BITS 64
DEFAULT REL

section .text
global _start

_start:
    mov rax, 0x1337131000
    mov r12, qword [r10]
    shr r12, 32
    shl r12, 32
