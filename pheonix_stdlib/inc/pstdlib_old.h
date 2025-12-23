/*
Pheonix Standard Library
*/

#pragma once

// Macros

#if defined(NULL)
#else
    #define NULL ((void*)0)
#endif

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
#define PNULL ((void*)0)


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
#elif defined(_WIN32)
    #include <memoryapi.h>
    #include <winnt.h>
    #include <windows.h>
    #include <processthreadsapi.h>
#endif

#define __MEMTYPE_EXEC__ 1 // Memory Type: Executable
#define __MEMTYPE_READ__ 2 // Memory Type: Read
#define __MEMTYPE_WRITE__ 3 // Memory Type: Write
#define __MEMTYPE_NONE__ 4 // Memory Type: None (Will be not accessed)

// Bool
#if defined(bool)
    #undef bool
#endif
#define bool _Bool // Bool (0 = False, 1 = True)
#define true ((bool)1)
#define false ((bool)0)

#define __PTR_ALIGNMENT 64 // Pointer Alignment (in bytes)

// Typedefs
typedef char byte_t; // Byte
typedef long long_t; // Long
typedef long long llong_t; // Long Long

typedef unsigned char ubyte_t; // Unsigned Byte
typedef unsigned char uchar_t; // Unsigned Character
typedef unsigned int uint_t; // Unsigned Integer
typedef unsigned short ushort_t; // Unsigned Short
typedef unsigned long ulong_t; // Unsigned Long
typedef unsigned long long ullong_t; // Unsigned Long Long

typedef unsigned long uptr_t; // Unsigned Pointer
typedef long ptr_t; // Signed Pointer

typedef long long len_t; // Signed Length
typedef long size_t; // Signed Size
typedef unsigned long long ulen_t; // Unsigned Length
typedef unsigned long usize_t; // Unsigned Size
typedef unsigned long long upos_t; // Unsigned Position

typedef unsigned char* uoff_t; // Unsigned Byte Pointer
typedef char* off_t; // Byte Pointer

typedef unsigned char flag_t; // 1 = True / 0 = False (Just an example can be used for any type of flag)

typedef char s8; // Signed 8-bit
typedef short s16; // Signed 16-bit
typedef int s32; // Signed 32-bit
typedef long long s64; // Signed 64-bit
typedef char u8; // Unsigned 8-bit
typedef short u16; // Unsigned 16-bit
typedef int u32; // Unsigned 32-bit
typedef long long u64; // Unsigned 64-bit

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

/*
PHM_Hdr: Pheonix Heap Memory Header
Reserved for Memory Allocation uses
*/
struct PHM_Hdr {
    usize_t size;
    u32 flags; // 32-bit Flags
    struct PHM_Hdr* next;
    usize_t next_count;
};

/*
PEHdlr: Pheonix Exit Handler
*/
struct PEHdlr {
    void (*func)(void);
    struct PEHdlr* next;
};

// Globals

// - Static

static struct PEHdlr* exit_handlers = NULL; // List of Exit functions

// Functions

// - Helpers

/*
Do a System Call

Needs Arguments based on OS, all of size llong_t, if the Machine doesn't support 64-bit then the values will be truncated to fit
*/
inline llong_t syscall(int id, ...) {
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
Align Pointer: Aligns a pointer 
*/
inline void* alignptr(void* ptr, usize_t alignment) {
    uptr_t addr = (uptr_t)ptr;
    return (void*)((addr + alignment - 1) & ~(alignment - 1));
}

/*
Align Buffer: Aligns a buffer and returns a pointer to the aligned memory
*/
inline void* alignbuf(void* buf, usize_t alignment) {
    return alignptr(buf, alignment);
}

/*
Is Aligned: Checks if a pointer is already aligned to the given boundry
*/
inline bool isaligned(void* ptr, usize_t alignment) {
    return ((uptr_t)ptr % alignment) == 0;
}

/*
Align Up: Aligns a value up to the nearest multiple of alignment
*/
inline usize_t alignup(usize_t val, usize_t alignment) {
    return (val + alignment - 1) & ~(alignment - 1);
}

/*
Align Down: Aligns a value down to the nearest multiple of the alignment
*/
inline usize_t aligndown(usize_t val, usize_t alignment) {
    return val & ~(alignment - 1);
}

// - Buffers/Memory

/* Copy Buffer -
Copy Memory from one place to another with specified size
*/
inline bool copybuf(void* source, void* dest, usize_t size) {
    if (size == 0) return true;
    else if (size < 0 || source == NULL || dest == NULL) return false;

    byte_t* dst = (byte_t*)dest;
    byte_t* src = (byte_t*)source;

    if (size < 32) {
        for (usize_t i = 0; i < size; i++) dst[i] = src[i];
        return true;
    }

    uptr_t p = ((uptr_t)dst) & (sizeof(u64) - 1);
    usize_t i = 0;
    if (p) {
        uptr_t to_align = (sizeof(u64) - p) & (sizeof(u64) - 1);
        if (to_align > size) to_align = size;
        for (; i < to_align; i++) dst[i] = src[i];
    }

    usize_t remain = size - 1;
    if (remain >= sizeof(u64)) {
        u64* wd = (u64*)(dst + i);
        u64* ws = (u64*)(src + i); 
        usize_t words = remain / sizeof(u64);
        while (words >= 4) {
            wd[0] = ws[0];
            wd[1] = ws[1];
            wd[2] = ws[2];
            wd[3] = ws[3];
            ws += 4;
            wd += 4;
            words -= 4;
        }
        while (words--) {
            *wd++ = *ws++;
        }
        i += ((size - i) / sizeof(u64)) * sizeof(u64);
    }

    for(; i < size; i++) dst[i] = src[i];
    return true;

}

/* Fill Buffer -
Fills Memory of specified size with the specified value
*/
inline bool fillbuf(void* buf, byte_t value, usize_t size) {
    if (size == 0) return true;
    else if (size < 0 || buf == NULL) return false;

    byte_t* dest = (byte_t*)buf;

    if (size < 32) {
        for (usize_t i = 0; i < size; i++) dest[i] = value;
        return true;
    }

    uptr_t p = ((uptr_t)dest) & (sizeof(u64) - 1);
    usize_t i = 0;
    if (p) {
        uptr_t to_align = (sizeof(u64) - p) & (sizeof(u64) - 1);
        if (to_align > size) to_align = size;
        for (; i < to_align; i++) dest[i] = value;
    }

    usize_t remain = size - 1;
    if (remain >= sizeof(u64)) {
        u64 pat = (u64)value * (u64)0x0101010101010101ULL;
        u64 *wd = (u64*)(dest + i);
        usize_t words = remain / sizeof(u64);
        while (words >= 4) {
            wd[0] = pat;
            wd[1] = pat;
            wd[2] = pat;
            wd[3] = pat;
            wd += 4;
            words -= 4;
        }
        while (words--) {
            *wd++ = pat;
        }
        i += ((size - i) / sizeof(u64)) * sizeof(u64);
    }

    for(; i < size; i++) dest[i] = value;
    return true;
}

/* Move Buffer -
Move Memory of specified size from one place to another
*/
inline bool movebuf(void* source, void* dest, usize_t size) {
    if (!copybuf(source, dest, size)) return false;
    return fillbuf(source, 0, size);
}

/* Compare Buffer -
Compare two blocks of Memory of the specified size

Returns:
1. false -> Not Same
2. true -> Same
*/
inline bool cmpbuf(void* a, void* b, usize_t size) {
    // Not yet implemented
}

/* Find Byte -
Finds the specified byte in a block of Memory of the specified size, returns the location.
*/
inline uoff_t findbyte(void* search_area, byte_t byte, usize_t size) {
    // Not Yet implemented
}

// - Allocation

/*
Extended Memory Alloc :
Allocate Memory on the Heap, Can provide type of memory, such as Exec
*/
inline void* exalloc(usize_t size, uint_t type, void* link) {
    void* ptr = NULL;
    uint_t prot = 0;

    #if defined(__linux__)
        if (type & __MEMTYPE_EXEC__) prot |= PROT_EXEC;
        if (type & __MEMTYPE_NONE__) prot |= PROT_NONE;
        if (type & __MEMTYPE_READ__) prot |= PROT_READ;
        if (type & __MEMTYPE_WRITE__) prot |= PROT_WRITE; 
        ptr = mmap(NULL, size + sizeof(struct PHM_Hdr), prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ptr == MAP_FAILED) {
            ptr = NULL;
        }
    #elif defined(_WIN32)
        if (type & __MEMTYPE_EXEC__ && type & __MEMTYPE_READ__ && type & __MEMTYPE_WRITE__) prot = PAGE_EXECUTE_READWRITE;
        else if (type & __MEMTYPE_EXEC__ && type & __MEMTYPE_READ__) prot = PAGE_EXECUTE_READ
        else if (type & __MEMTYPE_EXEC__) prot = PAGE_EXECUTE;
        else if (type & __MEMTYPE_NONE__) prot = PAGE_NOACCESS;
        else if (type & __MEMTYPE_WRITE__) prot = PAGE_READWRITE; 
        else if (type & __MEMTYPE_READ__) prot = PAGE_READONLY;
        else prot = PAGE_NOACCESS;

        ptr = VirtualAlloc(NULL, size + sizeof(PHM_Hdr), MEM_COMMIT | MEM_RESERVE, prot);
    #else
        ptr = NULL;
    #endif

    struct PHM_Hdr* hdr = (struct PHM_Hdr*)ptr;
    hdr->size = size;
    hdr->flags = 0; // Normal Allocated
    hdr->next = link ? link - sizeof(struct PHM_Hdr) : NULL;
    if (link) hdr->next_count++;

    return ptr + sizeof(struct PHM_Hdr);
}

/*
Memory Alloc -
Allocate Memory on the heap with type Read/Write
*/
inline void* alloc(usize_t size) {
    return exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, NULL);
}

/* De Alloc -
Deallocate the heap Allocated Memory
*/
inline bool dealloc(void* ptr) {
    if (ptr == NULL) return false;
    struct PHM_Hdr* hdr = ptr - sizeof(struct PHM_Hdr);

    if (hdr->next && hdr->next_count > 0) dealloc(hdr->next);

    if (hdr->flags != 0) return false; // DeAllocated Probably
    usize_t size = hdr->size + sizeof(struct PHM_Hdr);
    #if defined(__linux__)
        munmap((void*)hdr, size); // Hdr already points to the starting pos
    #elif defined(_WIN32)
        VirtualFree((void*)hdr, size, MEM_RELEASE);
    #else
        return false;
    #endif

    return true;
}

/*
Zeroed Memory Allocation -
Allocate Zeroed Memory on the heap with type Read/Write
*/
inline void* zalloc(usize_t size) {
    void* ptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, NULL);
    if (ptr == NULL) return ptr;
    if (!fillbuf(ptr, 0, size)) { dealloc(ptr); return NULL; }
    return ptr;
}

/*
Re Memory Allocation -
Reallocate Memory on the heap with type Read/Write
*/
inline void* ralloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, __MEMTYPE_WRITE__ | __MEMTYPE_READ__, ptr);
    if (nptr == NULL) { dealloc(ptr); return NULL; }
    return ptr;
}

/*
Zeroed Re Memory Allocation -
Reallocate Zeroed Memory on the heap with type Read/Write
*/
inline void* rzalloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, ptr);
    if (nptr == NULL) { dealloc(ptr); return NULL; }
    if (!fillbuf(nptr, 0, size)) { dealloc(ptr); return NULL; }
    return ptr;
}

// - Strings

/*
String Length -
Returns the length of a string (char*)
*/
inline usize_t strlen(const char* str) {
    const char* s = str;
    while (*s) s++;
    return s - str;
}

/*
String Copy -
Copy a string from one place to another
*/
inline bool strcopy(const char* src, char* dest) {
    return copybuf((void*)src, (void*)dest, strlen(src) + 1);
}

/*
String Size Copy -
Copy a string of the specified size from one place to another
*/
inline bool strscopy(const char* src, char* dest, usize_t size) {
    return copybuf((void*)src, (void*)dest, size);
}

// - Environment

/*
Retrieve Environment -
Retrieve and returns an environment variable
*/
inline char* retenv(const char* name) {
    #if defined(__linux__)
    #elif defined(_WIN32)
    #endif
    return NULL;
}

/*
Set Environment -
Set and returns an environment variable
*/
inline bool setenv(const char* name, const char* val, bool overwrite) {
    #if defined(__linux__)
    #elif defined(_WIN32)
    #endif
    return false;
}

// - General Utilities

/*
Append Exit Functions -
Add a new entry to a list of functions that is executed upon exit (not abort)

NOTE: These functions are executed from last appended to first appended
*/
inline bool aexitf(void (*func)(void)) {
    if (func == NULL) return false;

    struct PEHdlr* new_handler = (struct PEHdlr*)alloc(sizeof(struct PEHdlr));
    if (new_handler == NULL) return false;

    new_handler->func = func;
    new_handler->next = exit_handlers;
    exit_handlers = new_handler;

    return true;
}

/*
Exit -
Exits the program gracefully, flushing everything properly
*/
inline void exit(int status) {
    // Cleanup
    // Exit Functions
    struct PEHdlr* curef = exit_handlers;
    while (curef != NULL) {
        curef->func();
        struct PEHdlr* temp = curef;
        curef = curef->next;
        dealloc(temp); // Free the handler
    }

    #if defined(__linux__)
        // Calls exit_group
        #if __PARCH__ == x86_64
            syscall(231, (llong_t)status);
        #elif __PARCH__ == x86
            syscall(252, (llong_t)status);
        #elif __PARCH__ == arm32
            syscall(248, (llong_t)status);
        #elif __PARCH__ == arm64
            syscall(94, (llong_t)status);
        #endif
    #elif defined(_WIN32)
        ExitProcess((unsigned int)status);
    #endif
}

/*
Abort -
Immedietly Terminates the program with a core dump
*/
inline void abort(void) {
    #if defined(__linux__)
        // Calls exit_group with status 134 (128 + SIGABRT)
        #if __PARCH__ == x86_64
            syscall(231, 134);
        #elif __PARCH__ == x86
            syscall(252, 134);
        #elif __PARCH__ == arm32
            syscall(248, 134);
        #elif __PARCH__ == arm64
            syscall(94, 134);
        #endif
    #elif defined(_WIN32)
        TerminateProcess(GetCurrentProcess(), 6);
    #endif
}