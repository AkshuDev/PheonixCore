.section .text

.extern main
.extern exit
.extern __plib_reset_env

.global _start

_start:
    mov %rsp, %rax

    mov (%rax), %rdx // rdx = argc
    lea 16(%rax,%rdx,8), %rdi // rdi = envp

    xor %rsi, %rsi // rsi = envp_count
_start_count:
    mov (%rdi,%rsi,8), %rcx
    test %rcx, %rcx
    je _start_done
    inc %rsi
    jmp _start_count
_start_done:
    and $-16, %rsp // next push will align to 16
    sub $8, %rsp
    push %rax

    xor %rbp, %rbp
    // __plib_reset_env(envp, envp_count)
    call __plib_reset_env // rdi = envp, rsi = envp_count

    pop %rax
    add $8, %rsp

    // main(argc, argv)
    mov (%rax), %rdi // rdi = argc
    lea 8(%rax), %rsi // rsi = argv
    call main

    mov %eax, %edi
    call exit