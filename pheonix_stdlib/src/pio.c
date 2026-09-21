// Pheonix I/O C Source Code
#define __IPSTDLIB_BUILD
#include <pio.h>

#ifdef _WIN32
/*
Pheonix Standard Output Stream
*/
PIO_Stream raw_PStdoutStream = {
    .stream={
        .handle=-1,
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
PIO_Stream raw_PStdinStream = {
    .stream={
        .handle=-1,
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
PIO_Stream raw_PStderrStream = {
    .stream={
        .handle=-1,
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
PIO_Stream raw_PStdoutStream = {
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
PIO_Stream raw_PStdinStream = {
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
PIO_Stream raw_PStderrStream = {
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

PIO_Stream* PStdoutStream = &raw_PStdoutStream;
PIO_Stream* PStdinStream = &raw_PStdinStream;
PIO_Stream* PStderrStream = &raw_PStderrStream;

__IFN void __pio_init_streams(void) {
    #ifdef _WIN32
        PStderrStream->stream.handle = (uptr_t)GetStdHandle(STD_ERROR_HANDLE);
        PStdoutStream->stream.handle = (uptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
        PStdinStream->stream.handle = (uptr_t)GetStdHandle(STD_INPUT_HANDLE);
    #endif
}

__IFN PIO_Stream* sopen_file(const char* path, PStreamFlags flags) {
    if (!path) return PNULL;

    PIO_Stream* pio = (PIO_Stream*)zalloc(sizeof(PIO_Stream));
    if (!pio) return PNULL;

    #ifdef _WIN32
        DWORD access = 0;
        if (flags & PSTREAM_FLAG_READ) access |= GENERIC_READ;
        if (flags & PSTREAM_FLAG_WRITE) access |= GENERIC_WRITE;

        HANDLE h = CreateFileA(path, access, FILE_SHARE_READ, PNULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, PNULL);
        if (h == INVALID_HANDLE_VALUE) {
            pio->last_err = PIO_ERR_OPEN;
            return pio;
        }
        pio->stream.handle = (uptr_t)h;
    #else
        int mode = 0;
        int permissions = 0644;
        if (flags & PSTREAM_FLAG_READ) mode = O_RDONLY;
        if (flags & PSTREAM_FLAG_WRITE) mode = O_WRONLY | O_CREAT;
        if ((flags & PSTREAM_FLAG_READ) && (flags & PSTREAM_FLAG_WRITE)) mode = O_RDWR | O_CREAT;

        if (flags & PSTREAM_FLAG_APPEND) {
            if (mode & O_CREAT)
                mode &= ~(O_CREAT);
            mode |= O_APPEND;
        }

        int fd = open(path, mode, permissions);
        if (fd < 0) {
            pio->last_err = PIO_ERR_OPEN;
            return pio;
        }
        pio->stream.handle = (uptr_t)fd;
    #endif

    pio->last_err = PIO_ERR_NONE;
    pio->stream.readpos = 0;
    pio->stream.writepos = 0;
    pio->stream.filepos = 0;
    pio->stream.len = 0;
    pio->stream.flags = flags;
    pio->stream.buf = PNULL;

    return pio;
}

__IFN bool sclose(PIO_Stream* pio) {
    if (!pio) return false;

    #ifdef _WIN32
        CloseHandle((HANDLE)pio->stream.handle);
    #else
        close((int)pio->stream.handle);
    #endif

    if (pio->stream.buf) dealloc(pio->stream.buf);
    dealloc(pio);
    return true;
}

__IFN usize_t sread(PIO_Stream* pio, void* buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

    #ifdef _WIN32
        DWORD read = 0;
        if (!ReadFile((HANDLE)pio->stream.handle, buffer, (DWORD)size, &read, PNULL)) {
            pio->last_err = PIO_ERR_READ;
            return 0;
        }
        return (usize_t)read;
    #else
        long ret = read((int)pio->stream.handle, buffer, size);
        if (ret < 0) {
            pio->last_err = PIO_ERR_READ;
            return 0;
        }
        return (usize_t)ret;
    #endif
}

__IFN usize_t swrite(PIO_Stream* pio, const void* buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

    #ifdef _WIN32
        DWORD written = 0;
        if (!WriteFile((HANDLE)pio->stream.handle, buffer, (DWORD)size, &written, PNULL)) {
            pio->last_err = PIO_ERR_WRITE;
            return 0;
        }
        return (usize_t)written;
    #else
        long ret = write((int)pio->stream.handle, buffer, size);
        if (ret < 0) {
            pio->last_err = PIO_ERR_WRITE;
            return 0;
        }
        return (usize_t)ret;
    #endif
}

__IFN bool sseek(PIO_Stream* pio, long offset, int origin) {
    if (!pio) return false;

    #ifdef _WIN32
        LARGE_INTEGER li;
        li.QuadPart = offset;
        if (!SetFilePointerEx((HANDLE)pio->stream.handle, li, PNULL, origin)) {
            pio->last_err = PIO_ERR_SEEK;
            return false;
        }
        return true;
    #else
        long ret = lseek((int)pio->stream.handle, offset, origin);
        if (ret < 0) {
            pio->last_err = PIO_ERR_SEEK;
            return false;
        }
        return true;
    #endif
}

__IFN ulen_t stell(PIO_Stream* pio) {
    if (!pio) return (ulen_t)-1;
    #ifdef _WIN32
        LARGE_INTEGER pos;
        pos.QuadPart = 0;
        SetFilePointerEx((HANDLE)pio->stream.handle, pos, &pos, FILE_CURRENT);
        return (ulen_t)pos.QuadPart;
    #else
        long ret = lseek((int)pio->stream.handle, 0, SEEK_CUR);
        if (ret < 0) {
            pio->last_err = PIO_ERR_SEEK;
            return (ulen_t)-1;
        }
        return (ulen_t)ret;
    #endif
}

__IFN bool seof(PIO_Stream* pio) {
    if (!pio) return true;
    ulen_t cur = stell(pio);
    #ifdef _WIN32
        LARGE_INTEGER end;
        SetFilePointerEx((HANDLE)pio->stream.handle, end, &end, FILE_END);
        sseek(pio, cur, 0);
        return cur >= (ulen_t)end.QuadPart;
    #else
        long end = lseek((int)pio->stream.handle, 0, SEEK_END);
        sseek(pio, cur, 0);
        return cur >= (ulen_t)end;
    #endif
}

__IFN bool sflush(PIO_Stream* pio) {
	// TODO: Implement
	(void)pio;
	return true;
}

__IFN PIO_Errors slast_err(PIO_Stream* pio) {
    if (!pio) return PIO_ERR_UNK;
    return pio->last_err;
}

__IFN const char* get_lasterr_msg(void) {
    // Uses stderr stream
    PIO_Errors le = !s_stderr ? PIO_ERR_UNK : s_stderr->last_err;
    switch (le) {
        case PIO_ERR_NONE: return "None";
        case PIO_ERR_UNK: return "Unknown";
        case PIO_ERR_EOF: return "End of File (EOF)";
        case PIO_ERR_OPEN: return "Stream could not be opened";
        case PIO_ERR_READ: return "Stream could not be read from";
        case PIO_ERR_WRITE: return "Stream could not be written to";
        case PIO_ERR_SEEK: return "Stream seek failed";
        default: return "Unknown reason";
    }
}

__IFN int print(const char* str, usize_t size) {
    if (!str) return -1;
    #ifdef _WIN32
        if (PStdoutStream->stream.handle == INVALID_HANDLE_VALUE)
            return -2;
        int chars_written;
        WriteConsole(PStdoutStream->stream.handle, str, size, &chars_written, PNULL);
        return chars_written;
    #else
        swrite(PStdoutStream, str, size);
    #endif
    return -4;
}

__IFN int vfprints(PIO_Stream* pio, const char* format, va_list ap) {
    if (!pio || !format) return -1;

    char* s = 0;
    usize_t len_s = 0;
    char buf64[64] = {0};

    int written = 0;

    int size_of_v = sizeof(int);
    uint width_of_v = 0; // as much as possible
    uint precision_of_v = 0; // as much as possible

    bool base_prefix = false;
    char signed_prefix = '\0';
    bool signed_prefix_on_positive = true;

    bool parsing_flags = false;
    bool invalid = false;

    bool in_precision = false;
    bool in_width = false;

    for (const char* p = format; *p; p++) {
        if (*p != '%') {
            swrite(pio, p, 1);
            written++;
            continue;
        }

        // Reset
        size_of_v = sizeof(int);
        base_prefix = false;
        signed_prefix = '\0';
        signed_prefix_on_positive = true;
        invalid = false;
        in_precision = false;
        in_width = false;
        precision_of_v = 0;
        width_of_v = 0;

        p++;
        if (!*p) break;
        parsing_flags = true;
        while (parsing_flags) { // Parse 1
            switch (*p) {
                case 'l': {
                    in_precision = false;
                    in_width = false;

                    size_of_v = sizeof(i64);
                    p++;
                    break;
                }
                case 'h': {
                    in_precision = false;
                    in_width = false;
                    
                    size_of_v = sizeof(i16);
                    p++;
                    break;
                }
                case 'n': {
                    in_precision = false;
                    in_width = false;
                    
                    size_of_v = sizeof(i8);
                    p++;
                    break;
                }

                case '!': {
                    in_precision = false;
                    in_width = false;
                    
                    signed_prefix_on_positive = !signed_prefix_on_positive;
                    p++;
                    break;
                }
                case '-': {
                    in_precision = false;
                    in_width = false;
                    
                    signed_prefix = '-';
                    p++;
                    break;
                }
                case '+': {
                    in_precision = false;
                    in_width = false;
                    
                    signed_prefix = '+';
                    p++;
                    break;
                }
                case ' ': {
                    in_precision = false;
                    in_width = false;
                    
                    signed_prefix = ' ';
                    p++;
                    break;
                }

                case '#': {
                    in_precision = false;
                    in_width = false;
                    
                    base_prefix = true;
                    p++;
                    break;
                }

                case '.': {
                    in_width = false;
                    
                    precision_of_v = 0;
                    in_precision = true;
                    p++;
                    break;
                }

                default: {
                    if (c_is_digit(*p)) {
                        if (in_precision) {
                            precision_of_v = append_u64(precision_of_v, char_to_digit(*p));
                        } else if (in_width) {
                            width_of_v = append_u64(width_of_v, char_to_digit(*p));
                        } else {
                            // counted as width
                            in_width = true;
                            width_of_v = 0;
                            width_of_v = append_u64(width_of_v, char_to_digit(*p));
                        }
                        p++;
                        break;
                    }
                    parsing_flags = false;
                    break;
                }
            }
            if (!*p) {
                invalid = true;
                break;
            }
        }
        if (invalid) break;

        switch (*p) { // Parse 2
            case '%': {
                swrite(pio, p, 1);
                written++;
                break;
            }
            
            case 's': {
                s = va_arg(ap, char*);
                if (!s) s = "(null)";
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'c': {
                char char_v = (char)va_arg(ap, int);
                written += swrite(pio, &char_v, 1);
                break;
            }

            case 'i':
            case 'd': {
                i64 int_v;
                switch (size_of_v) {
                    case sizeof(i8): int_v = (i64)((i8)va_arg(ap, int)); break;
                    case sizeof(i16): int_v = (i64)((i16)va_arg(ap, int)); break;
                    case sizeof(int): int_v = (i64)((int)va_arg(ap, int)); break;
                    case sizeof(i64): int_v = (i64)((i64)va_arg(ap, i64)); break;
                    default: int_v = (i64)((int)va_arg(ap, int)); break;
                }
                s = i64_to_str(int_v, buf64, 10);
                if (!s) s = "(invalid int)";
                if (signed_prefix != '\0') {
                    if (signed_prefix_on_positive && int_v >= 0) {
                        written += swrite(pio, &signed_prefix, 1);
                    } else if (!signed_prefix_on_positive && int_v < 0) {
                        written += swrite(pio, &signed_prefix, 1);
                    }
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'u': {
                u64 uint_v;
                switch (size_of_v) {
                    case sizeof(i8): uint_v = (u64)((u8)va_arg(ap, int)); break;
                    case sizeof(i16): uint_v = (u64)((u16)va_arg(ap, int)); break;
                    case sizeof(int): uint_v = (u64)((uint)va_arg(ap, uint)); break;
                    case sizeof(i64): uint_v = (u64)((u64)va_arg(ap, u64)); break;
                    default: uint_v = (u64)((uint)va_arg(ap, uint)); break;
                }
                s = u64_to_str(uint_v, buf64, 10);
                if (!s) s = "(invalid uint)";
                if (signed_prefix != '\0' && signed_prefix_on_positive) {
                    written += swrite(pio, &signed_prefix, 1);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'o': {
                u64 uint_v;
                switch (size_of_v) {
                    case sizeof(i8): uint_v = (u64)((u8)va_arg(ap, int)); break;
                    case sizeof(i16): uint_v = (u64)((u16)va_arg(ap, int)); break;
                    case sizeof(int): uint_v = (u64)((uint)va_arg(ap, int)); break;
                    case sizeof(i64): uint_v = (u64)((u64)va_arg(ap, u64)); break;
                    default: uint_v = (u64)((uint)va_arg(ap, uint)); break;
                }
                s = u64_to_str(uint_v, buf64, 8);
                if (!s) s = "(invalid octal)";
                if (base_prefix) {
                    written += swrite(pio, "0o", 2);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'x': {
                u64 uint_v;
                switch (size_of_v) {
                    case sizeof(i8): uint_v = (u64)((u8)va_arg(ap, int)); break;
                    case sizeof(i16): uint_v = (u64)((u16)va_arg(ap, int)); break;
                    case sizeof(int): uint_v = (u64)((uint)va_arg(ap, int)); break;
                    case sizeof(i64): uint_v = (u64)((u64)va_arg(ap, u64)); break;
                    default: uint_v = (u64)((uint)va_arg(ap, uint)); break;
                }
                s = u64_to_str(uint_v, buf64, 16);
                if (!s) s = "(invalid hex)";
                if (base_prefix) {
                    written += swrite(pio, "0x", 2);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'X': {
                u64 uint_v;
                switch (size_of_v) {
                    case sizeof(i8): uint_v = (u64)((u8)va_arg(ap, int)); break;
                    case sizeof(i16): uint_v = (u64)((u16)va_arg(ap, int)); break;
                    case sizeof(int): uint_v = (u64)((uint)va_arg(ap, int)); break;
                    case sizeof(i64): uint_v = (u64)((u64)va_arg(ap, u64)); break;
                    default: uint_v = (u64)((uint)va_arg(ap, uint)); break;
                }
                s = u64_to_str(uint_v, buf64, 16);
                for (char* sptr = s; *sptr; sptr++) {
                    if (c_is_alpha(*sptr)) {
                        *sptr = (*sptr & 0xDF);
                    }
                }
                if (!s) s = "(invalid hex)";
                if (base_prefix) {
                    written += swrite(pio, "0x", 2);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'b': {
                u64 uint_v;
                switch (size_of_v) {
                    case sizeof(i8): uint_v = (u64)((u8)va_arg(ap, int)); break;
                    case sizeof(i16): uint_v = (u64)((u16)va_arg(ap, int)); break;
                    case sizeof(int): uint_v = (u64)((uint)va_arg(ap, int)); break;
                    case sizeof(i64): uint_v = (u64)((u64)va_arg(ap, u64)); break;
                    default: uint_v = (u64)((uint)va_arg(ap, uint)); break;
                }
                s = u64_to_str(uint_v, buf64, 2);
                if (!s) s = "(invalid binary)";
                if (base_prefix) {
                    written += swrite(pio, "0b", 2);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'p': {
                u64 uint_v = (u64)va_arg(ap, void*);
                s = u64_to_str(uint_v, buf64, 16);
                if (!s) s = "(invalid pointer)";
                written += swrite(pio, "0x", 2);
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'P': {
                u64 uint_v = (u64)va_arg(ap, void*);
                s = u64_to_str(uint_v, buf64, 16);
                if (!s) s = "(invalid pointer)";
                for (char* sptr = s; *sptr; sptr++) {
                    if (c_is_alpha(*sptr)) {
                        *sptr = (*sptr & 0xDF);
                    }
                }
                written += swrite(pio, "0x", 2);
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }
            case 'f': {
                double double_v;
                switch (size_of_v) {
                    case sizeof(i64): double_v = (double)((double)va_arg(ap, double)); break;
                    default: double_v = (double)((float)va_arg(ap, double)); break;
                }
                s = double_to_str(double_v, buf64, precision_of_v <= 16 && precision_of_v > 0 ? precision_of_v : 16);
                if (!s) s = "(invalid float)";
                len_s = strlen(s);
                written += swrite(pio, s, len_s > width_of_v && width_of_v > 0 ? width_of_v : len_s);
                break;
            }

            default: {
                swrite(pio, p, 1);
                written++;
                break;
            }
        }
    }

    return written;
}

__IFN int fprints(PIO_Stream* pio, const char* format, ...) {
    va_list ap;
    start_va(ap, format);
    int ret = vfprints(pio, format, ap);
    end_va(ap);
    return ret;
}

__IFN int perror(const char* format, ...) {
    va_list ap;
    start_va(ap, format);
    int ret = vfprints(s_stderr, format, ap);
    end_va(ap);

    const char* err = get_lasterr_msg();
    fprints(s_stderr, "\n    : %s\n", err);
    
    return ret;
}
