// Pheonix Dynamic Loader C Source Code
#define __IPSTDLIB_BUILD
#include <pdl.h>

#include <pstdlib.h>
#include <pio.h>

// Internal structures
typedef enum PDLFormat {
    PDL_FORMAT_UNKNOWN = 0,
    PDL_FORMAT_ELF,
    PDL_FORMAT_PE
};

struct PDLHdr {
	const char* path; // Library path
	
	enum PDLFormat format; // Library format
	PDLOpenModes open_mode; // Mode via which lib was opened
	PDLOpenFlags open_flags; // Flags via which lib was opened

	void* lib_base; // Loaded library pointer
	usize_t lib_size; // Loaded library size
};

static enum PDLFormat _pdl_get_lib_format(PIO_Stream* s, size_t size) {
	if (!s) return PDL_FORMAT_UNKNOWN;
	if (!sseek(s, 0, SEEK_SET)) return PDL_FORMAT_UNKNOWN;
}

__IFN PDLHandle pdl_open(const char* path, PDLOpenModes mode, PDLOpenFlags flags) {
	PIO_Stream* f = sopen_file(path, PSTREAM_FLAG_READ | PSTREAM_FLAG_BINARY);
	if (!f) return PDL_INVALID_HANDLE;

	sclose(f);
}
