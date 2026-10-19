// Pheonix Dynamic Loader
#pragma once

#error "Not yet complete for use!"

#include "pstdlib.h"

// Typedefs
typedef uptr_t PDLHandle; // Pheonix Dynamic Loader Handle
typedef uptr_t PDLSymbol; // Pheonix Dynamic Loader Symbol

// Macros
#define PDL_INVALID_HANDLE (PDLHandle)0

// Enums

/*
Pheonix Dynamic Loader Open Flags
*/
typedef enum {
	PDL_FLAG_OPEN_LOCAL = 1 << 1, // Allows symbol access only by the binary/library which opened the shared library
	PDL_FLAG_OPEN_GLOBAL = 1 << 2 // Allows symbol access by any binary/library
} PDLOpenFlags;

/*
Pheonix Dynamic Loader Open Modes
*/
typedef enum {
	PDL_MODE_OPEN_LAZY = 0, // Opens the shared library, but resolves the symbols only when they are accessed
	PDL_MODE_OPEN_NOW // Opens the shared library and resolves all symbols at once
} PDLOpenModes;

#ifdef __cplusplus
extern "C" {
#endif

/* Pheonix Dynamic Loader Open -
Opens a shared library from the specified path, and loads it into memory according to flags and mode

Returns:
	PDLHandle - Handle to the shared libary loaded in memory
*/
__IFN PDLHandle pdl_open(const char* path, PDLOpenModes mode, PDLOpenFlags flags);

/* Pheonix Dynamic Loader Close -
Closes an already open shared library which was loaded in memory

Returns:
	bool - True if closing succeeds, else False
*/
__IFN bool pdl_close(PDLHandle handle);

/* Pheonix Dynamic Loader Get Symbol -
Retrieves a symbol from a loaded shared library

Returns:
	PDLSymbol - Handle to the shared libary's symbol
*/
__IFN PDLSymbol pdl_get_sym(PDLHandle handle);

#ifdef __cplusplus
}
#endif