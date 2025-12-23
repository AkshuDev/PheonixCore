// Pheonix I/O C Source Code
#define __PSTDLIB_BUILD
#include <pio.h>

__IFN PIO_Stream* sopen_file(const char *path, PStreamFlags flags) {
    if (!path) return PNULL;

    PIO_Stream *pio = (PIO_Stream*)zalloc(sizeof(PIO_Stream));
    if (!pio) return PNULL;

#ifdef _WIN32
    DWORD access = 0;
    if (flags & PSTREAM_FLAG_READ) access |= GENERIC_READ;
    if (flags & PSTREAM_FLAG_WRITE) access |= GENERIC_WRITE;

    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

__IFN bool sclose(PIO_Stream *pio) {
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

__IFN usize_t sread(PIO_Stream *pio, void *buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

#ifdef _WIN32
    DWORD read = 0;
    if (!ReadFile((HANDLE)pio->stream.handle, buffer, (DWORD)size, &read, NULL)) {
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

__IFN usize_t swrite(PIO_Stream *pio, const void *buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

#ifdef _WIN32
    DWORD written = 0;
    if (!WriteFile((HANDLE)pio->stream.handle, buffer, (DWORD)size, &written, NULL)) {
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

__IFN bool sseek(PIO_Stream *pio, long offset, int origin) {
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

__IFN ulen_t stell(PIO_Stream *pio) {
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

__IFN bool seof(PIO_Stream *pio) {
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

__IFN bool sflush(PIO_Stream *pio) { return true; }

__IFN PIO_Errors slast_err(PIO_Stream *pio) {
    if (!pio) return PIO_ERR_UNK;
    return pio->last_err;
}

__IFN int print(const char *str, usize_t size) {
    if (str == PNULL) return -1;
#if defined(_WIN32)
    if (PStdoutStream.stream.handle == INVALID_HANDLE_VALUE)
        return -2;
    int chars_written;
    WriteConsole(PStdoutStream.stream.handle, str, size, &chars_written, NULL);
    return chars_written;
#else
    swrite(&PStdoutStream, str, size);
#endif
    return -4;
}

__IFN int perror(const char *format, ...) {
    return 0;
}

__IFN int fprint(PIO_Stream *pio, const char *format, ...) {
    if (!pio) return -1;
    return 0;
}
