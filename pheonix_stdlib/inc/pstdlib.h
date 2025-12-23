/*
Pheonix Standard Library
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Macros

#if defined(NULL)
#else
    #define NULL ((void*)0) // NULL
#endif

/*
Pheonix Style Null -
```c
void*(0)
```

May need casting like for preventing warnings -
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
#endif

#define __MEMTYPE_EXEC__ 1 // Memory Type: Executable
#define __MEMTYPE_READ__ 2 // Memory Type: Read
#define __MEMTYPE_WRITE__ 3 // Memory Type: Write
#define __MEMTYPE_NONE__ 4 // Memory Type: None (Will be not accessed)

// Bool
#if __STDC_VERSION__ >= 199901L
    #include <stdbool.h> // Better and safer
#elif defined(__cplusplus) // Already keywords
#else
    #if defined(bool)
        #if defined(true)
        #else
            #define true((bool)1)
        #endif
        #if defined(false)
        #else
            #define false ((bool)0)
        #endif
    #else
        typedef char bool; // Bool (0 = False, 1 = True)
        #if defined(true)
        #else
            #define true ((bool)1)
        #endif
        #if defined(false)
        #else
            #define false ((bool)0)
        #endif
    #endif
#endif

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
typedef long psize_t; // Signed Size
typedef unsigned long long ulen_t; // Unsigned Length
typedef unsigned long usize_t; // Unsigned Size
typedef unsigned long long upos_t; // Unsigned Position

typedef unsigned char *uoff_t; // Unsigned Byte Pointer
typedef char *poff_t; // Byte Pointer

typedef unsigned char flag_t; // 1 = True / 0 = False (Just an example can be used for any type of flag)

typedef char s8; // Signed 8-bit
typedef short s16; // Signed 16-bit
typedef int s32; // Signed 32-bit
typedef long long s64; // Signed 64-bit
typedef char u8; // Unsigned 8-bit
typedef short u16; // Unsigned 16-bit
typedef int u32; // Unsigned 32-bit
typedef long long u64; // Unsigned 64-bit

// Enums

/*
PStreamFlags: Pheonix Stream Flags
Provides the Flags for PStream
*/
typedef enum {
    PSTREAM_FLAG_READ = 1 << 0, // Read
    PSTREAM_FLAG_WRITE = 1 << 1, // Write
    PSTREAM_FLAG_EXEC = 1 << 2, // Execute
    PSTREAM_FLAG_APPEND = 1 << 3, // Append
    PSTREAM_FLAG_EOF = 1 << 4, // End Of File
    PSTREAM_FLAG_ERR = 1 << 5, // Error
    PSTREAM_FLAG_BINARY = 1 << 6, // Binary
} PStreamFlags;

// Structures

/*
PStream: Pheonix Stream.

Provides a unified interface for reading, writing, and seeking
across various data sources such as files, memory buffers, or network streams.
*/
typedef struct PStream {
    uptr_t handle; // Internal Stream Handle
    uoff_t readpos; // Current Reading position
    uoff_t writepos; // Current Writing position
    uoff_t filepos; // Current Logical File Position corresponding to the buffer
    ulen_t len; // Length
    PStreamFlags flags; // Flags
    u8 *buf; // Internal buffer
    int md_err; // Meta Data: Stores Last Error
} PStream;

/*
PHM_Hdr: Pheonix Heap Memory Header
Reserved for Memory Allocation uses
*/
struct PHM_Hdr {
    usize_t size; // Size of allocation
    u32 flags; // 32-bit Flags
    struct PHM_Hdr *next; // Next linked allocation
    usize_t next_count; // Number of linked allocations
};

// Functions
#if defined(_WIN32)
    #if defined(__IPSTDLIB_BUILD)
        #define __IFN declspec(dllexport) // Internal Function
    #else
        #define __IFN declspec(dllimport) // Internal Function
    #endif
#else
    #define __IFN // Internal Function
#endif

/*
Do a System Call

Needs Arguments based on OS, all of size llong_t, if the Machine doesn't support
64-bit then the values will be truncated to fit

NOTE: Doesn't Support Windows as windows itself prefers using NTDLL
*/
__IFN llong_t __plib_syscall(int id, ...);

/* Copy Buffer -
Copy Memory from one place to another with specified size
*/
__IFN bool copybuf(void *source, void *dest, usize_t size);

/* Fill Buffer -
Fills Memory of specified size with the specified value
*/
__IFN bool fillbuf(void *buf, byte_t value, usize_t size);

/* Move Buffer -
Move Memory of specified size from one place to another
*/
__IFN bool movebuf(void *source, void *dest, usize_t size); 

/* Compare Buffer -
Compare two blocks of Memory of the specified size

Returns:
1. false -> Not Same
2. true -> Same
*/
__IFN bool cmpbuf(void *a, void *b, usize_t size);

/* Find Byte -
Finds the specified byte in a block of Memory of the specified size, returns the
location.
*/
__IFN uoff_t findbyte(void *search_area, byte_t byte, usize_t size);

/*
Extended Memory Alloc :
Allocate Memory on the Heap, Can provide type of memory, such as Exec
*/
__IFN void *exalloc(usize_t size, uint_t type, void *link); 

/*
Memory Alloc -
Allocate Memory on the heap with type Read/Write
*/
__IFN void* alloc(usize_t size);

/* De Alloc -
Deallocate the heap Allocated Memory
*/
__IFN bool dealloc(void* ptr);

/*
Zeroed Memory Allocation -
Allocate Zeroed Memory on the heap with type Read/Write
*/
__IFN void* zalloc(usize_t size);

/*
Re Memory Allocation -
Reallocate Memory on the heap with type Read/Write
*/
__IFN void *ralloc(void *ptr, usize_t size);

/*
Zeroed Re Memory Allocation -
Reallocate Zeroed Memory on the heap with type Read/Write
*/
__IFN void *rzalloc(void *ptr, usize_t size);

#ifdef __cplusplus
}
#endif

