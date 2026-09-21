/*
Pheonix Standard Library

NOTES:
    its recommended to compile without normal STDLIB to force Pheonix Stdlib, as well as the Pheonix Startup Runtime (PSRT) so specific functios like retenv or setenv work.
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

#define __PHM_HDR_FLAG_ALLOCATED__ (1 << 0)
#define __PHM_HDR_FLAG_AUTO_FREE__ (1 << 1)

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

#if defined(_WIN64)
	// 64-bit (long long)

    typedef unsigned long long uptr_t; // Unsigned Pointer
    typedef long long ptr_t; // Signed Pointer
    typedef unsigned long long usize_t; // Unsigned Size
    typedef long long psize_t; // Signed Size
#elif defined(__LP64__)
	// 64-bit

    typedef unsigned long uptr_t; // Unsigned Pointer
    typedef long ptr_t; // Signed Pointer
    typedef unsigned long usize_t; // Unsigned Size
    typedef long psize_t; // Signed Size
#else
	// 32-bit

    typedef unsigned int uptr_t; // Unsigned Pointer
    typedef int ptr_t; // Signed Pointer
    typedef unsigned int usize_t; // Unsigned Size
    typedef int psize_t; // Signed Size
#endif

typedef long long len_t; // Signed Length
typedef unsigned long long ulen_t; // Unsigned Length
typedef unsigned long long upos_t; // Unsigned Position

typedef unsigned char* uoff_t; // Unsigned Byte Pointer
typedef char* poff_t; // Byte Pointer

typedef unsigned char flag_t; // 1 = True / 0 = False (Just an example can be used for any type of flag)

typedef char s8; // Signed 8-bit
typedef short s16; // Signed 16-bit
typedef int s32; // Signed 32-bit
typedef long long s64; // Signed 64-bit
typedef char i8; // Signed 8-bit
typedef short i16; // Signed 16-bit
typedef int i32; // Signed 32-bit
typedef long long i64; // Signed 64-bit
typedef unsigned char u8; // Unsigned 8-bit
typedef unsigned short u16; // Unsigned 16-bit
typedef unsigned int u32; // Unsigned 32-bit
typedef unsigned long long u64; // Unsigned 64-bit

typedef unsigned int uint; // Unsigned int

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
    u8* buf; // Internal buffer
    int md_err; // Meta Data: Stores Last Error
} PStream;

/*
PHM_Hdr: Pheonix Heap Memory Header
Reserved for Memory Allocation uses
*/
struct PHM_Hdr {
    usize_t size; // Size of allocation
    u32 flags; // 32-bit Flags
    usize_t auto_free_idx; // Auto free idx (if auto_free == true)
    struct PHM_Hdr* next; // Next linked allocation
    usize_t next_count; // Number of linked allocations
};

/*
PEHdlr: Pheonix Exit Handler
*/
struct PEHdlr {
    void (*func)(void);
    struct PEHdlr* next;
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

// Limits
#define INT64_MAX 0x7FFFFFFFFFFFFFFFLL
#define INT64_MIN 0x8000000000000000LL
#define INT32_MAX 0x7FFFFFFFLL
#define INT32_MIN 0x80000000LL
#define INT16_MAX 0x7FFFLL
#define INT16_MIN 0x8000LL
#define INT8_MAX 0x7FLL
#define INT8_MIN 0x80LL

#define INT_MAX INT32_MAX
#define INT_MIN INT32_MIN

#define UINT64_MAX 0xFFFFFFFFFFFFFFFFULL
#define UINT32_MAX 0xFFFFFFFFULL
#define UINT16_MAX 0xFFFFULL
#define UINT8_MAX 0xFFULL

#define UINT_MAX UINT32_MAX
#define UINT_MIN UINT32_MIN

// Quick Maths
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/*
Do a System Call

Needs Arguments based on OS, all of size llong_t, if the Machine doesn't support
64-bit then the values will be truncated to fit

NOTE: Doesn't Support Windows as windows itself prefers using NTDLL
*/
__IFN llong_t __plib_syscall(int id, ...);

/*
Reset Environment Variables -
Do not use, only to be used by PSRT (Pheonix Startup Runtime)
*/
__IFN void __plib_reset_env(char** envp, usize_t envp_count);

/* Copy Buffer -
Copy Memory from one place to another with specified size
*/
__IFN bool copybuf(void* dest, const void* source, usize_t size);

/* Fill Buffer -
Fills Memory of specified size with the specified value
*/
__IFN bool fillbuf(void* buf, byte_t value, usize_t size);

/* Move Buffer -
Move Memory of specified size from one place to another
*/
__IFN bool movebuf(void* dest, const void* source, usize_t size); 

/* Compare Buffer -
Compare two blocks of Memory of the specified size, and returns the byte difference of the first differing byte, and smallest int value incase of error
*/
__IFN int cmpbuf(const void* a, const void* b, usize_t size);

/* Find Byte -
Finds the specified byte in a block of Memory of the specified size, returns the
location.
*/
__IFN uoff_t findbyte(const void* search_area, byte_t byte, usize_t size);

/*
Extended Memory Alloc :
Allocate Memory on the Heap, Can provide type of memory, such as Exec
*/
__IFN void* exalloc(usize_t size, uint_t type, void* link, bool auto_free); 

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
__IFN void* ralloc(void* ptr, usize_t size);

/*
Zeroed Re Memory Allocation -
Reallocate Zeroed Memory on the heap with type Read/Write
*/
__IFN void* rzalloc(void* ptr, usize_t size);

/*
Align Pointer: Aligns a pointer 
*/
__IFN void* alignptr(void* ptr, usize_t alignment);

/*
Align Buffer: Aligns a buffer and returns a pointer to the aligned memory
*/
__IFN void* alignbuf(void* buf, usize_t alignment);

/*
Is Aligned: Checks if a pointer is already aligned to the given boundry
*/
__IFN bool isaligned(void* ptr, usize_t alignment);

/*
Align Up: Aligns a value up to the nearest multiple of alignment
*/
__IFN usize_t alignup(usize_t val, usize_t alignment);

/*
Align Down: Aligns a value down to the nearest multiple of the alignment
*/
__IFN usize_t aligndown(usize_t val, usize_t alignment);

/*
String Length -
Returns the length of a string (char*)
*/
__IFN usize_t strlen(const char* str);

/*
String Copy -
Copy a string from one place to another
*/
__IFN bool strcopy(char* dest, const char* src);

/*
String Size Copy -
Copy a string of the specified size from one place to another
*/
__IFN bool strscopy(char* dest, const char* src, usize_t size);

/*
String Compare -
Compare a string with another string

Returns:
1. true = Equal
2. false = Not Equal
*/
__IFN bool strcmp(const char* a, const char* b);

/*
String Size Compare -
Compare specified bytes of a string with another string

Returns:
1. true = Equal
2. false = Not Equal
*/
__IFN bool strncmp(const char* a, const char* b, usize_t size);

/*
String Find Character  -
Find the specified occurance of the provided character and return the part of the string with that character and after it
*/
__IFN const char* strfindc(const char* str, char c, usize_t occurance);

/*
String Split -
Find the specified occurance of the provided character and return a new string of either the part before or after the character
*/
__IFN char* strsplit(const char* str, char c, usize_t occurance, bool first_part);

/*
Retrieve Environment -
Retrieve and returns an environment variable
*/
__IFN char* retenv(const char* name);

/*
Set Environment -
Set and returns an environment variable
*/
__IFN bool setenv(const char* name, const char* val, bool overwrite);

/*
i64_to_str: Int 64 to String

Convert an integer of size 8 bytes or 64 bits to string
*/
__IFN char* i64_to_str(i64 v, char* buf, int base);

/*
int_to_str: Int to String

Convert an integer of size 4 bytes or 32 bits to string
*/
#define int_to_str(v, buf, base) i64_to_str((int)v, buf, base)

/*
i32_to_str: Int 32 to String

Convert an integer of size 4 bytes or 32 bits to string
*/
#define i32_to_str(v, buf, base) i64_to_str((i32)v, buf, base)

/*
i16_to_str: Int 16 to String

Convert an integer of size 2 bytes or 16 bits to string
*/
#define i16_to_str(v, buf, base) i64_to_str((i16)v, buf, base)

/*
i8_to_str: Int 8 to String

Convert an integer of size 1 bytes or 8 bits to string
*/
#define i8_to_str(v, buf, base) i64_to_str((i8)v, buf, base)

/*
u64_to_str: Unsigned Int 64 to String

Convert an unsigned integer of size 8 bytes or 64 bits to string
*/
__IFN char* u64_to_str(u64 v, char* buf, int base);

/*
uint_to_str: Unsigned Int to String

Convert an unsigned integer of size 4 bytes or 32 bits to string
*/
#define uint_to_str(v, buf, base) u64_to_str((uint)v, buf, base)

/*
u32_to_str: Unsigned Int 32 to String

Convert an unsigned integer of size 4 bytes or 32 bits to string
*/
#define u32_to_str(v, buf, base) u64_to_str((u32)v, buf, base)

/*
u16_to_str: Unsigned Int 16 to String

Convert an unsigned integer of size 2 bytes or 16 bits to string
*/
#define u16_to_str(v, buf, base) u64_to_str((u16)v, buf, base)

/*
u8_to_str: Unsigned Int 8 to String

Convert an unsigned integer of size 1 bytes or 8 bits to string
*/
#define u8_to_str(v, buf, base) u64_to_str((u8)v, buf, base)

/*
double_to_str: double to String

Convert a double to string
*/
__IFN char* double_to_str(double v, char* buf, int precision);

/*
float_to_str: float to String

Convert a float to string
*/
#define float_to_str(v, buf, precision) double_to_str((float)v, buf, precision)

/*
Character to Digit
Converts Characters to digits
*/
__IFN int char_to_digit(char c);

/*
str_to_i64: String to Int 64

Convert a string to an integer of size 8 bytes or 64 bits
*/
__IFN i64 str_to_i64(const char* str, int base);

/*
str_to_int: String to Int

Convert a string to an integer of size 4 bytes or 32 bits
*/
#define str_to_int(str, base) (int)str_to_i64(str, base)

/*
str_to_i32: String to Int 32

Convert a string to an integer of size 4 bytes or 32 bits
*/
#define str_to_i32(str, base) (i32)str_to_i64(str, base)

/*
str_to_i16: String to Int 16

Convert a string to an integer of size 2 bytes or 16 bits
*/
#define str_to_i16(str, base) (i16)str_to_i64(str, base)

/*
str_to_i8: String to Int 8

Convert a string to an integer of size 1 bytes or 8 bits
*/
#define str_to_i8(str, base) (i8)str_to_i64(str, base)

/*
str_to_u64: String to Unsigned Int 64

Convert a string to an unsigned integer of size 8 bytes or 64 bits
*/
__IFN u64 str_to_u64(const char* str, int base);

/*
str_to_uint: String to Unsigned Int

Convert a string to an unsigned integer of size 4 bytes or 32 bits
*/
#define str_to_uint(str, base) (uint)str_to_u64(str, base)

/*
str_to_u32: String to Unsigned Int 32

Convert a string to an unsigned integer of size 4 bytes or 32 bits
*/
#define str_to_u32(str, base) (u32)str_to_u64(str, base)

/*
str_to_u16: String to Unsigned Int 16

Convert a string to an unsigned integer of size 2 bytes or 16 bits
*/
#define str_to_u16(str, base) (u16)str_to_u64(str, base)

/*
str_to_u8: String to Unsigned Int 8

Convert a string to an unsigned integer of size 1 bytes or 8 bits
*/
#define str_to_u8(str, base) (u8)str_to_u64(str, base)

/*
str_to_double: String to double

Convert a string to an double
*/
__IFN double str_to_double(const char* str);

/*
str_to_float: String to float

Convert a string to an float
*/
#define str_to_float(str) (float)str_to_double(str)

/*
c_is_alpha: Character is Alphabetical
Returns true if character is Alphabetical else false
*/
__IFN bool c_is_alpha(char c);

/*
c_is_digit: Character is Numeric
Returns true if character is a representation of a digit else false
*/
__IFN bool c_is_digit(char c);

/*
c_is_alphanum: Character is Alphanumeric
Returns true if character is Alphanumeric else false
*/
__IFN bool c_is_alphanum(char c);

/*
is_alpha: String is Alphabetical
Returns true if string is Alphabetical else false
*/
__IFN bool is_alpha(const char* s);

/*
is_digit: String is Numeric
Returns true if string is a representation of a number else false
*/
__IFN bool is_digit(const char* s);

/*
is_alphanum: String is Alphanumeric
Returns true if string is Alphanumeric else false
*/
__IFN bool is_alphanum(const char* s);

/*
is_float: String is float
Returns true if string is a representation of float else false
*/
__IFN bool is_float(const char* s);

/*
Append Int 64
Decimal Concatinates the 2 specified arguments, and returns them.
*/
__IFN i64 append_i64(i64 a, i64 b);

/*
Append Int
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_int(a, b) (int)append_i64((i64)((int)a), (i64)((int)b));

/*
Append Int 32
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_i32(a, b) (i32)append_i64((i64)((i32)a), (i64)((i32)b));

/*
Append Int 16
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_i16(a, b) (i16)append_i64((i64)((i16)a), (i64)((i16)b));

/*
Append Int 8
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_i8(a, b) (i8)append_i64((i64)((i8)a), (i64)((i8)b));

/*
Append Unsigned Int 64
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_u64(a, b) (u64)append_i64((i64)((u64)a), (i64)((u64)b));

/*
Append Unsigned Int
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_uint(a, b) (uint)append_i64((i64)((uint)a), (i64)((uint)b));

/*
Append Unsigned Int 32
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_u32(a, b) (u32)append_i64((i64)((u32)a), (i64)((u32)b));

/*
Append Unsigned Int 16
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_u16(a, b) (u16)append_i64((i64)((u16)a), (i64)((u16)b));

/*
Append Unsigned Int 8
Decimal Concatinates the 2 specified arguments, and returns them.
*/
#define append_u8(a, b) (u8)append_i64((i64)((u8)a), (i64)((u8)b));

/*
Append Exit Functions -
Add a new entry to a list of functions that is executed upon exit (not abort)

NOTE: These functions are executed from last appended to first appended
*/
__IFN bool aexitf(void (*func)(void));

/*
Exit -
Exits the program gracefully, flushing everything properly
*/
__IFN __attribute__((noreturn)) void exit(int status);

/*
Abort -
Immedietly Terminates the program with a core dump
*/
__IFN __attribute__((noreturn)) void abort(void);

// Externals

/*
start_va: Start Variadic Arguments
Starts Variadic Arguments
*/
#define start_va __builtin_va_start
/*
va_arg: Variadic Argument
Returns the next Variadic Argument
*/
#define va_arg __builtin_va_arg
/*
end_va: End Variadic Arguments
Ends Variadic Arguments
*/
#define end_va __builtin_va_end
/*
va_list: Variadic Argument List
*/
#define va_list __builtin_va_list

#ifdef __cplusplus
}
#endif

