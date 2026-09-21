.section .text

.extern main
.extern exit
.extern __plib_reset_env

.global _start

_start:
    mov %esp, %eax

    mov (%eax), %ebx // ebx = argc
    lea 16(%eax,%ebx,8), %edx // edx = envp

    xor %ecx, %ecx // ecx = envp_count
_start_count:
    mov (%edx,%ecx,8), %esi
    test %esi, %esi
    je _start_done
    inc %ecx
    jmp _start_count
_start_done:
    and $-16, %esp // next push will align to 16
    sub $8, %esp
    push %eax

    xor %ebp, %ebp
    // __plib_reset_env(envp, envp_count)

	push ecx
	push edx
    call __plib_reset_env // edx = envp, ecx = envp_count

    pop %eax
    add $8, %esp

    // main(argc, argv)
    mov (%eax), %ecx // rdi = argc
    lea 8(%eax), %edx // rsi = argv

	push edx
	push ecx
    call main // main(int argc, char** argv)

    mov %eax, %edi
    call exit