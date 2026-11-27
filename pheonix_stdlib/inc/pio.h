// Pheonix I/O
#pragma once

#include "pstdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

// Linux and windows share same values
#if !defined(SEEK_SET)
	#define SEEK_SET 0 // Seek from beginning of file
#endif
#if !defined(SEEK_CUR)
	#define SEEK_CUR 1 // Seek from current position
#endif
#if !defined(SEEK_END)
	#define SEEK_END 2 // Seek from end of file
#endif

/*
Pheonix I/O Error Codes
*/
typedef enum {
    PIO_ERR_NONE = 0, // No Error
    PIO_ERR_OPEN, // Error while opening
	PIO_ERR_CLOSE, // Error while closing
    PIO_ERR_READ, // Error while reading
    PIO_ERR_WRITE, // Error while writing
    PIO_ERR_SEEK, // Error while seeking
	PIO_ERR_MD, // Error while retrieving file metadata
    PIO_ERR_EOF, // Unexpected End Of File
    PIO_ERR_UNK // Unknown cause of Error
} PIO_Errors;

/*
Pheonix I/O File Metadata - Stores metadata of a file
*/
typedef struct {
	bool valid; // Is the structure valid and filled

	timestamp_t creation_time; // The time of creation of the file
	timestamp_t modified_time; // The time of modification of the file
	timestamp_t last_access_time; // The time of the last access of the file

	ulen_t file_size; // The size of the file in bytes
} PIO_FileMD;

/*
Pheonix I/O String Metadata - Stores metadata of a string
*/
typedef struct {
	bool valid; // Is the structure valid and filled
	ulen_t string_size; // The size of the string buffer in bytes
} PIO_StringMD;

/*
Pheonix I/O Directory Entry - Stores entry of a directory
*/
typedef struct {
    const char* name; // Name of the file
} PIO_DirectoryEntry;

/*
Pheonix I/O Stream - allows usage of proper debug during IO usage
*/
typedef struct {
	union {
		PIO_FileMD file_md;
		PIO_StringMD string_md;
	};

    PStream stream; // Stream
	const char* last_err_xstr; // eXtended information in the from of string, of the last error
	const char* last_err_func; // The name of the function where the last error occured
} PIO_Stream;

extern PIO_Stream* PStdoutStream; // Standard output stream
extern PIO_Stream* PStdinStream; // Standard input stream
extern PIO_Stream* PStderrStream; // Standard error stream

#define s_stdout PStdoutStream // Standard output stream
#define s_stdin PStdinStream // Standard input stream
#define s_stderr PStderrStream // Standard error stream

/*
__pio_init_streams - Initialize Streams (Auto done when using PSRT)
Initializes Basic Streams for Operating systems with varying stream handles such as Windows
*/
__IFN void __pio_init_streams(void);

/*
sfile_md - Stream File Metadata
Requests metadata for specified file (path if `s` is NULL, else uses the specified stream), and writes it in `out` in the form of `PIO_FileMD` structure.

Returns true if succesfull and false if failed.

NOTE: Does not register errors for `get_lasterror` and such functions due to variable usage between stream and path.
*/
__IFN bool sfile_md(const char* path, PIO_FileMD* out, PIO_Stream* s);

/*
sopen_file - Stream Open File
Opens a file at the given path with specified PStreamFlags (Read, Write, etc). Returns a pointer to a PIO_Stream, or NULL if opening fails
*/
__IFN PIO_Stream* sopen_file(const char* path, PStreamFlags flags);

/*
sopen_dir - Stream Open Directory
Opens a directory at the given path. Returns a pointer to a PIO_Stream, or NULL if opening fails
*/
__IFN PIO_Stream* sopen_dir(const char* path);

/*
sopen_string - Stream Open String
Creates a string stream with the given metadata. Returns a pointer to a PIO_Stream, or NULL if creation fails
*/
__IFN PIO_Stream* sopen_string(char* str, usize_t size, PStreamFlags flags);

/*
sclose - Stream Close
Closes the provided PIO_Stream and releases any allocated resources

Supported Stream Types:
1. File
2. Directory
3. String
*/
__IFN bool sclose(PIO_Stream* pio);

/*
sread - Stream Read
Reads `size` bytes from the PIO_Stream into the given buffer
Returns the number of bytes successfully read

Supported Stream Types:
1. File
2. <DIRECTORY UNDER DEVELOPMENT, USAGE DISALLOWED FOR NOW>
3. String

Special Cases:

1. If stream is a directory stream, then `buffer` should point to `PIO_DirectoryEntry` Structure and `size` should strictly be the size of `PIO_DirectoryEntry` structure.
*/
__IFN usize_t sread(PIO_Stream* pio, void* buffer, usize_t size);

/*
sgetc - Stream Get Character
Reads 1 byte from the PIO_Stream and returns it, '\0' on EOF or failure (could also be a valid byte in the stream, so check last error)

Supported Stream Types:
1. File
2. String
*/
__IFN char sgetc(PIO_Stream* pio);

/*
sungetc - Stream Un-Get Character
Moves the file cursor 1 byte back in the PIO_Stream

Supports all stream types
*/
__IFN void sungetc(PIO_Stream* pio);

/*
swrite - Stream Write
Writes `size` bytes from the buffer to the PIO_Stream
Returns the number of bytes successfully written

Supported Stream Types:
1. File
2. String
*/
__IFN usize_t swrite(PIO_Stream* pio, const void* buffer, usize_t size);

/*
sseek - Stream Seek
Moves the internal file pointer of the PIO_Stream based on offset and origin (SEEK_SET, SEEK_CUR, SEEK_END). Returns true on success, false on failure

Supported Stream Types:
1. File
2. <DIRECTORY UNDER DEVELOPMENT, USAGE DISALLOWED FOR NOW>
3. String
*/
__IFN bool sseek(PIO_Stream* pio, len_t offset, int origin);

/*
stell - Stream Tell
Returns the current position of the internal file pointer within the PIO_Stream. (negative if error)

Supports all stream types
*/
__IFN len_t stell(PIO_Stream* pio);

/*
get_lasterr_msg: Get Last Error Message
Uses STDERR stream to retrieve the last error and returns its string representation
*/
__IFN const char* get_lasterr_msg(void);

/*
vfprints - Variadic Argument Formatted Print to Stream
Writes a formatted string to the specified PIO_Stream. Returns the number of characters written or a negative value on error

Requires Variadic Argument List
*/
__IFN int vfprints(PIO_Stream* pio, const char* format, va_list ap);

/*
fprints - Formatted Print to Stream
Writes a formatted string to the specified PIO_Stream. Returns the number of characters written or a negative value on error
*/
__IFN int fprints(PIO_Stream* pio, const char* format, ...);

/*
fprint - Formatted Print
Writes a formatted string to stdout stream. Returns the number of characters written or a negative value on error
*/
#define fprint(format, ...) fprints((s_stdout), (format), ##__VA_ARGS__)

/*
fmsprint - Formatted Max String Print
Writes a formatted string to another string obeying a max size. Returns the number of characters written or a negative value on error
*/
__IFN int fmsprint(char* dst, usize_t max_size, const char* format, ...);

/*
fsprint - Formatted String Print
Writes a formatted string to another string. Returns the number of characters written or a negative value on error
*/
#define fsprint(dst, format, ...) fmsprint((dst), (dst) ? strlen((dst)) : 0, (format), ##__VA_ARGS__)

/*
print - Formatted Print to Standard Output
Writes a formatted string to stdout. Returns the number of characters written or a negative value on error
*/
__IFN int print(const char* str, usize_t size);

/*
fperror - Formatted Print to Standard Error
Writes a formatted string to stderr. Returns the number of characters written or a negative value on error
*/
__IFN int fperror(const char* format, ...);

/*
seof - Stream End-of-File
Checks if the PIO_Stream has reached EOF. Returns true if EOF is reached, false otherwise
*/
__IFN bool seof(PIO_Stream* pio);

/*
sflush - Stream Flush
Flushes any buffered data in the PIO_Stream to the underlying storage. Returns true on success
*/
__IFN bool sflush(PIO_Stream* pio);

/*
slast_err - Stream Last Error
Retrieves the last error encountered by the PIO_Stream
Returns a PIO_Errors value
*/
__IFN PIO_Errors slast_err(PIO_Stream* pio);

/*
slast_err_msg - Stream Last Error Message
Retrieves the last error encountered by the PIO_Stream
Returns the string version of the error
*/
__IFN const char* slast_err_msg(PIO_Stream* pio);

/*
slast_err_xmsg - Stream Last eXtended Error Message
Retrieves the last error encountered by the PIO_Stream, and fills out corrosponding parameters if not NULL -
'xmsg': eXtended Message of the error
'func': The name of the function which had the last error

Returns the string version of the error
*/
__IFN const char* slast_xerr_msg(PIO_Stream* pio, const char** xmsg, const char** func);

/*
get_lasterr - Get Last Error
Retrieves the last error encountered by stderr stream
Returns a PIO_Errors value
*/
#define get_lasterr() slast_err(s_stderr)

/*
get_lasterr_msg - Stream Last Error Message
Retrieves the last error encountered by stderr stream
Returns the string version of the error
*/
#define get_lasterr_msg() slast_err_msg(s_stderr)

/*
get_xlasterr_msg - Stream eXtended Last Error Message
Retrieves the last error encountered by stderr stream, and fills out corrosponding parameters if not NULL -
'xmsg': eXtended Message of the error
'func': The name of the function which had the last error

Returns the string version of the error
*/
#define get_xlasterr_msg(xmsg, func) slast_xerr_msg(s_stderr, (xmsg), (func))

#ifdef __cplusplus
}
#endif
