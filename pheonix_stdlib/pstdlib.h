/*
Pheonix Standard Library
*/

#pragma once

// Macros

/*
Pheonix Style Null - 
```c
void*(0)
```

May need casting like - 
```c
char* str = (char*)PNULL;
```
*/
#define PNULL (void*)0 


#if defined(__x86_64__) || defined(_M_X64)
    #define __PARCH__ x86_64
#elif defined(__i386__) || defined(_M_IX86)
    #define __PARCH__ x86
#elif defined(__aarch64__)
    #define __PARCH__ arm64
#elif defined(__arm__)
    #define __PARCH__ arm32
#else
    #define __PARCH__ unknown
#endif

#if defined(__linux__)
#include <sys/mman.h>
#endif

#define __MEMTYPE_EXEC__ 1 // Memory Type: Executable
#define __MEMTYPE_READ__ 2 // Memory Type: Read
#define __MEMTYPE_WRITE__ 3 // Memory Type: Write
#define __MEMTYPE_NONE__ 4 // Memory Type: None (Will be not accessed)

// Typedefs
typedef char byte_t; // Byte
typedef long long_t; // Long
typedef long long llong_t; // Long Long

typedef unsigned char ubyte_t; // Unsigned Byte
typedef ubyte_t uchar_t; // Unsigned Character
typedef unsigned int uint_t; // Unsigned Integer
typedef unsigned short ushort_t; // Unsigned Short
typedef unsigned long ulong_t; // Unsigned Long
typedef unsigned long long ullong_t; // Unsigned Long Long

typedef llong_t len_t; // Signed Length
typedef long_t size_t; // Signed Size
typedef ullong_t ulen_t; // Unsigned Length
typedef ulong_t usize_t; // Unsigned Size
typedef ullong_t upos_t; // Unsigned Position

typedef ubyte_t* uoff_t; // Unsigned Byte Pointer
typedef byte_t* off_t; // Byte Pointer

typedef byte_t flag_t; // 1 = True / 0 = False

// Structures

/*
PStream: Pheonix Stream.

Provides a unified interface for reading, writing, and seeking
across various data sources such as files, memory buffers, or network streams.
*/
typedef struct PStream {
    uoff_t readpos; // Current Reading position
    uoff_t writepos; // Current Writing position
    ulen_t len; // Length
    uint_t flags; // Flags
    off_t buf; // Internal Buffer
    flag_t useBuf; // Use Internal Buffer for speed
    int md_err; // Meta Data: Stores Last Error
} PStream;

// Functions

/*
Do a System Call

Needs Arguments based on OS, all of size llong_t, if the Machine doesn't support 64-bit then the values will be truncated to fit
*/
inline llong_t __plib_syscall(int id, ...) {
    llong_t ret = 0;
    llong_t *args = (llong_t *)(&id + 1);

    #if __PARCH__ == x86_64
        #if defined(__linux__) || defined(__unix__)
            llong_t a[6] = {0};
            for(int i=0;i<6;i++) a[i] = args[i];
            asm volatile (
                "mov %[num], %%rax\n\t"
                "mov %[a1], %%rdi\n\t"
                "mov %[a2], %%rsi\n\t"
                "mov %[a3], %%rdx\n\t"
                "mov %[a4], %%r10\n\t"
                "mov %[a5], %%r8\n\t"
                "mov %[a6], %%r9\n\t"
                "syscall\n\t"
                "mov %%rax, %[ret]"
                : [ret] "=r"(ret)
                : [num] "r"((llong_t)id),
                [a1] "r"(a[0]),
                [a2] "r"(a[1]),
                [a3] "r"(a[2]),
                [a4] "r"(a[3]),
                [a5] "r"(a[4]),
                [a6] "r"(a[5])
                : "rax","rdi","rsi","rdx","r10","r8","r9","rcx","r11","memory"
            );
        #elif defined(_WIN32)
            llong_t a[6] = {0};
            for(int i=0;i<6;i++) a[i] = args[i];
            asm volatile(
                "mov %[num], %%rax\n\t"
                "mov %[a1], %%rcx\n\t"
                "mov %[a2], %%rdx\n\t"
                "mov %[a3], %%r8\n\t"
                "mov %[a4], %%r9\n\t"
                "mov %[a5], %%r10\n\t"
                "mov %[a6], %%r11\n\t"
                "syscall\n\t"
                "mov %%rax, %[ret]"
                : [ret] "=r"(ret)
                : [num] "r"((llong_t)id),
                [a1] "r"(a[0]),
                [a2] "r"(a[1]),
                [a3] "r"(a[2]),
                [a4] "r"(a[3]),
                [a5] "r"(a[4]),
                [a6] "r"(a[5])
                : "rax","rcx","rdx","r8","r9","r10","r11","memory"
            );
        #endif

    #elif __PARCH__ == x86
        #if defined(__linux__) || defined(__unix__)
            int a[5] = {0};
            for(int i=0;i<5;i++) a[i] = (int)args[i];
            asm volatile(
                "mov %[num], %%eax\n\t"
                "mov %[a1], %%ebx\n\t"
                "mov %[a2], %%ecx\n\t"
                "mov %[a3], %%edx\n\t"
                "mov %[a4], %%esi\n\t"
                "mov %[a5], %%edi\n\t"
                "int $0x80\n\t"
                "mov %%eax, %[ret]"
                : [ret] "=r"(ret)
                : [num] "r"(id),
                [a1] "r"(a[0]),
                [a2] "r"(a[1]),
                [a3] "r"(a[2]),
                [a4] "r"(a[3]),
                [a5] "r"(a[4])
                : "eax","ebx","ecx","edx","esi","edi","memory"
            );
        #elif defined(_WIN32)
            // Windows x86 syscalls are tricky; need int 0x2e or ntdll stubs
            ret = 0;
        #endif

    #elif __PARCH__ == arm64
        llong_t a[8] = {0};
        for(int i=0;i<8;i++) a[i] = args[i];
        asm volatile(
            "mov x8, %[num]\n\t"
            "mov x0, %[a1]\n\t"
            "mov x1, %[a2]\n\t"
            "mov x2, %[a3]\n\t"
            "mov x3, %[a4]\n\t"
            "mov x4, %[a5]\n\t"
            "mov x5, %[a6]\n\t"
            "mov x6, %[a7]\n\t"
            "mov x7, %[a8]\n\t"
            "svc 0\n\t"
            "mov %[ret], x0"
            : [ret] "=r"(ret)
            : [num] "r"((llong_t)id),
            [a1] "r"(a[0]),
            [a2] "r"(a[1]),
            [a3] "r"(a[2]),
            [a4] "r"(a[3]),
            [a5] "r"(a[4]),
            [a6] "r"(a[5]),
            [a7] "r"(a[6]),
            [a8] "r"(a[7])
            : "x0","x1","x2","x3","x4","x5","x6","x7","x8","memory"
        );

    #elif __PARCH__ == arm32
        llong_t a[7] = {0};
        for(int i=0;i<7;i++) a[i] = args[i];
        asm volatile(
            "mov r7, %[num]\n\t"
            "mov r0, %[a1]\n\t"
            "mov r1, %[a2]\n\t"
            "mov r2, %[a3]\n\t"
            "mov r3, %[a4]\n\t"
            "mov r4, %[a5]\n\t"
            "mov r5, %[a6]\n\t"
            "mov r6, %[a7]\n\t"
            "svc 0\n\t"
            "mov %[ret], r0"
            : [ret] "=r"(ret)
            : [num] "r"((llong_t)id),
            [a1] "r"(a[0]),
            [a2] "r"(a[1]),
            [a3] "r"(a[2]),
            [a4] "r"(a[3]),
            [a5] "r"(a[4]),
            [a6] "r"(a[5]),
            [a7] "r"(a[6])
            : "r0","r1","r2","r3","r4","r5","r6","r7","memory"
        );

    #else
        ret = -1; // unknown arch
    #endif

    return ret;
}

/*
Allocate Memory on the Heap, Can provide type of memory, such as Exec
*/
inline void* memalloc(usize_t size, uint_t type) {
    void* ptr = PNULL;
    uint_t prot = 0;

    #if defined(__linux__)
        if (type & __MEMTYPE_EXEC__) prot |= PROT_EXEC;
        if (type & __MEMTYPE_NONE__) prot |= PROT_NONE;
        if (type & __MEMTYPE_READ__) prot |= PROT_READ;
        if (type & __MEMTYPE_WRITE__) prot |= PROT_WRITE; 
        ptr = mmap(PNULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    #endif
}