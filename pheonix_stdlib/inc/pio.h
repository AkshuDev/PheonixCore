// Pheonix I/O
#pragma once

#include <pstdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) || defined(__unix__)
    #include <fcntl.h>
    #include <unistd.h>
    #define __lstdin 0
    #define __lstdout 1
    #define __lstderr 2
#elif defined(_WIN32)
    #include <windows.h>
#endif

/*
Pheonix I/O Error Codes
*/
typedef enum {
    PIO_ERR_NONE = 0, // No Error
    PIO_ERR_OPEN, // Error while opening
    PIO_ERR_READ, // Error while reading
    PIO_ERR_WRITE, // Error while writing
    PIO_ERR_SEEK, // Error while seeking
    PIO_ERR_EOF, // Unexpected End Of File
    PIO_ERR_UNK // Unknown cause of Error
} PIO_Errors;

/*
Pheonix I/O Stream - allows usage of proper debug during accessing last error
*/
typedef struct {
    PStream stream;
    PIO_Errors last_err;
} PIO_Stream;

#if defined(_WIN32)
/*
Pheonix Standard Output Stream
*/
static PIO_Stream PStdoutStream = {
    .stream={
        .handle=(uptr_t)GetStdHandle(STD_OUTPUT_HANDLE),
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_WRITE,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};

/*
Pheonix Standard Input Stream
*/
static PIO_Stream PStdinStream = {
    .stream={
        .handle=(uptr_t)GetStdHandle(STD_INPUT_HANDLE),
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_READ,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};


/*
Pheonix Standard Error Stream
*/
static PIO_Stream PStderrStream = {
    .stream={
        .handle=(uptr_t)GetStdHandle(STD_ERROR_HANDLE),
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_WRITE,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};
#else
/*
Pheonix Standard Output Stream
*/
static PIO_Stream PStdoutStream = {
    .stream={
        .handle=__lstdout,
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_WRITE,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};

/*
Pheonix Standard Input Stream
*/
static PIO_Stream PStdinStream = {
    .stream={
        .handle=__lstdin,
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_READ,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};


/*
Pheonix Standard Error Stream
*/
static PIO_Stream PStderrStream = {
    .stream={
        .handle=__lstderr,
        .readpos=0,
        .writepos=0,
        .filepos=0,
        .len=0,
        .flags=PSTREAM_FLAG_WRITE,
        .buf=(u8*)PNULL,
        .md_err=0
    },
    .last_err=PIO_ERR_NONE
};
#endif

/*
sopen_file - Stream Open File
Opens a file at the given path with specified PStreamFlags
(Read, Write, etc.). Returns a pointer to a PIO_Stream,
or NULL if opening fails.
*/
__IFN PIO_Stream* sopen_file(const char *path, PStreamFlags flags);

/*
sclose - Stream Close
Closes the provided PIO_Stream and releases any allocated
resources. Returns true on success, false on failure.
*/
__IFN bool sclose(PIO_Stream *pio);

/*
sread - Stream Read
Reads `size` bytes from the PIO_Stream into the given buffer.
Returns the number of bytes successfully read.
*/
__IFN usize_t sread(PIO_Stream *pio, void *buffer, usize_t size);

/*
swrite - Stream Write
Writes `size` bytes from the buffer to the PIO_Stream.
Returns the number of bytes successfully written.
*/
__IFN usize_t swrite(PIO_Stream *pio, const void *buffer, usize_t size);

/*
sseek - Stream Seek
Moves the internal file pointer of the PIO_Stream based on
offset and origin (SEEK_SET, SEEK_CUR, SEEK_END). Returns
true on success, false on failure.
*/
__IFN bool sseek(PIO_Stream *pio, long offset, int origin);

/*
stell - Stream Tell
Returns the current position of the internal file pointer
within the PIO_Stream.
*/
__IFN ulen_t stell(PIO_Stream *pio);

/*
fprint - Formatted Print to Stream
Writes a formatted string to the specified PIO_Stream. Returns
the number of characters written or a negative value on error.
*/
__IFN int fprint(PIO_Stream *pio, const char *format, ...);

/*
print - Formatted Print to Standard Output
Writes a formatted string to stdout. Returns the number of
characters written or a negative value on error.
*/
__IFN int print(const char *str, usize_t size);

/*
perror - Formatted Print to Standard Error
Writes a formatted string to stderr. Returns the number of
characters written or a negative value on error.
*/
__IFN int perror(const char *format, ...);

/*
seof - Stream End-of-File
Checks if the PIO_Stream has reached EOF. Returns true if
EOF is reached, false otherwise.
*/
__IFN bool seof(PIO_Stream *pio);

/*
sflush - Stream Flush
Flushes any buffered data in the PIO_Stream to the
underlying storage. Returns true on success.
*/
__IFN bool sflush(PIO_Stream *pio);

/*
slast_err - Stream Last Error
Retrieves the last error encountered by the PIO_Stream.
Returns a PIO_Errors value.
*/
__IFN PIO_Errors slast_err(PIO_Stream *pio);

#ifdef __cplusplus
}
#endif
