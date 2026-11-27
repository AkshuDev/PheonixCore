// Pheonix I/O C Source Code
#define __IPSTDLIB_BUILD
#include <pio.h>

#include <pstdlib.h>

#if defined(__linux__) || defined(__unix__)
    #include <fcntl.h>
    #include <unistd.h>
	#include <dirent.h>
	#include <sys/stat.h>

    #define __lstdin 0
    #define __lstdout 1
    #define __lstderr 2

	/*
	Pheonix Standard Output Stream
	*/
	PIO_Stream raw_PStdoutStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=__lstdout,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_WRITE,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};

	/*
	Pheonix Standard Input Stream
	*/
	PIO_Stream raw_PStdinStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=__lstdin,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_READ,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};

	/*
	Pheonix Standard Error Stream
	*/
	PIO_Stream raw_PStderrStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=__lstderr,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_WRITE,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};
#elif defined(_WIN32)
    #include <windows.h>
	#include <fileapi.h>

	/*
	Pheonix Standard Output Stream
	*/
	PIO_Stream raw_PStdoutStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=-1,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_WRITE,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};

	/*
	Pheonix Standard Input Stream
	*/
	PIO_Stream raw_PStdinStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=-1,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_READ,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};


	/*
	Pheonix Standard Error Stream
	*/
	PIO_Stream raw_PStderrStream = {
		.stream={
			.type=PSTREAM_TYPE_FILE,
			.handle=-1,
			.filepos=0,
			.sfilepos=0,
			.spos=0,
			.len=0,
			.flags=PSTREAM_FLAG_WRITE,
			.buf=(u8*)PNULL,
			.md_err=0
		},
		.last_err_xstr=PNULL,
		.last_err_func=PNULL
	};
#endif

#if !defined(PIO_STREAM_BUF_CAP)
	#define PIO_STREAM_BUF_CAP 0x2000 // 8KB
#endif

#ifndef PSTREAM_BUF_CHUNK_SIZE
    #define PSTREAM_BUF_CHUNK_SIZE 0x1000
#endif

#define PSTREAM_BUF_REMAINING(s) ((s)->len - ((s)->filepos - (s)->spos))
#define PSTREAM_BUF_DATA(s) ((s)->buf + ((s)->filepos - (s)->spos))

#define WIN32_FILETIME_EPOCH_OFFSET 11644473600ULL
#define WIN32_FILETIME_RESOLUTION 10000000ULL

PIO_Stream* PStdoutStream = &raw_PStdoutStream;
PIO_Stream* PStdinStream = &raw_PStdinStream;
PIO_Stream* PStderrStream = &raw_PStderrStream;

__IFN void __pio_init_streams(void) {
    #if defined(_WIN32)
        PStderrStream->stream.handle = (uptr_t)GetStdHandle(STD_ERROR_HANDLE);
        PStdoutStream->stream.handle = (uptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
        PStdinStream->stream.handle = (uptr_t)GetStdHandle(STD_INPUT_HANDLE);
    #endif
}

__IFN bool sfile_md(const char* path, PIO_FileMD* out, PIO_Stream* s) {
	if ((!path && !s) || !out) return false;

	PIO_FileMD ret = {0};

	#if defined(_WIN32)
		if (s) {
			FILE_BASIC_INFO data = {0};
			if (!GetFileInformationByHandleEx(p->stream.handle, FileBasicInfo, &data, sizeof(data))) return false;

			ULARGE_INTEGER ull;

			ull.LowPart = ((FILETIME)data.CreationTime).dwLowDateTime;
			ull.HighPart = ((FILETIME)data.CreationTime).dwHighDateTime;
			ret.creation_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);
			
			ull.LowPart = ((FILETIME)data.LastWriteTime).dwLowDateTime;
			ull.HighPart = ((FILETIME)data.LastWriteTime).dwHighDateTime;
			ret.modified_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);

			ull.LowPart = ((FILETIME)data.LastAccessTime).dwLowDateTime;
			ull.HighPart = ((FILETIME)data.LastAccessTime).dwHighDateTime;
			ret.last_access_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);

			FILE_STANDARD_INFO data2 = {0};
			if (!GetFileInformationByHandleEx(p->stream.handle, FileStandardInfo, &data2, sizeof(data2))) return false;
			ret.file_size = (ulen_t)data2.EndOfFile.QuadPart;
		} else {
			WIN32_FILE_ATTRIBUTE_DATA data = {0};
			if (!GetFileAttributesExA(path, GetFileExInfoStandard, &data)) return false;

			ULARGE_INTEGER ull;

			ull.LowPart = data.ftCreationTime.dwLowDateTime;
			ull.HighPart = data.ftCreationTime.dwHighDateTime;
			ret.creation_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);
			
			ull.LowPart = data.ftLastWriteTime.dwLowDateTime;
			ull.HighPart = data.ftLastWriteTime.dwHighDateTime;
			ret.modified_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);

			ull.LowPart = data.ftLastAccessTime.dwLowDateTime;
			ull.HighPart = data.ftLastAccessTime.dwHighDateTime;
			ret.last_access_time = (timestamp_t)((ull.QuadPart / WIN32_FILETIME_RESOLUTION) - WIN32_FILETIME_EPOCH_OFFSET);

			ret.file_size = (ulen_t)(((u64)data.nFileSizeHigh << 32) & 0xFFFFFFFF00000000ULL) | ((u64)data.nFileSizeLow & 0xFFFFFFFFULL);
		}
    #else
		struct stat st;
		if (s) {
			#if __PARCH__ == x86_64
				if (__plib_syscall(0x5, (llong_t)s->stream.handle, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == x86
				if (__plib_syscall(0x6C, (llong_t)s->stream.handle, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == arm64
				if (__plib_syscall(0x50, (llong_t)s->stream.handle, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == arm32
				if (__plib_syscall(0x6C, (llong_t)s->stream.handle, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#endif
		} else {
			#if __PARCH__ == x86_64
				if (__plib_syscall(0x4, (llong_t)(uptr_t)path, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == x86
				if (__plib_syscall(0x6A, (llong_t)(uptr_t)path, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == arm64
				if (__plib_syscall(0x4F, -100LL, (llong_t)(uptr_t)path, (llong_t)(uptr_t)&st, 0LL, 0, 0, 0) < 0) return false;
			#elif __PARCH__ == arm32
				if (__plib_syscall(0x6A, (llong_t)(uptr_t)path, (llong_t)(uptr_t)&st, 0, 0, 0, 0) < 0) return false;
			#endif
		}

		ret.creation_time = (timestamp_t)st.st_ctime;
		ret.modified_time = (timestamp_t)st.st_mtime;
		ret.last_access_time = (timestamp_t)st.st_atime;
		ret.file_size = (ulen_t)st.st_size;
    #endif

	*out = ret;
	out->valid = true;
	return true;
}

__IFN PIO_Stream* sopen_file(const char* path, PStreamFlags flags) {
    if (!path) return PNULL;

    PIO_Stream* pio = (PIO_Stream*)zalloc(sizeof(PIO_Stream));
    if (!pio) return PNULL;

    #if defined(_WIN32)
		pio->stream.handle = INVALID_HANDLE_VALUE;

        DWORD access = 0;
        if (flags & PSTREAM_FLAG_READ) access |= GENERIC_READ;
        if (flags & PSTREAM_FLAG_WRITE) access |= GENERIC_WRITE;

        HANDLE h = CreateFileA(path, access, FILE_SHARE_READ, PNULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, PNULL);
        if (h == INVALID_HANDLE_VALUE) {
			pio->stream.md_err = PIO_ERR_OPEN;
            pio->last_err_xstr = "'CreateFileA' returned an Invalid Handle";
			pio->last_err_func = "sopen_file";
			goto error;
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
			pio->stream.md_err = PIO_ERR_OPEN;
            pio->last_err_xstr = "'open' returned negative file descriptor";
			pio->last_err_func = "sopen_file";
            
			goto error;
        }
        pio->stream.handle = (uptr_t)fd;
    #endif

    pio->last_err_xstr = PNULL;
	pio->last_err_func = PNULL;
	pio->stream.md_err = PIO_ERR_NONE;
    pio->stream.filepos = 0;
	pio->stream.sfilepos = 0;
	pio->stream.spos = 0;
    pio->stream.len = 0;
	pio->stream.cap = 0;
    pio->stream.flags = flags;
	pio->stream.type = PSTREAM_TYPE_FILE;
    pio->stream.buf = PNULL;

	sfile_md(PNULL, &pio->file_md, pio); // Could fail, but ignore error
    return pio;

	error: {
		//? There is no way a error occurs after file opening is complete
		dealloc(pio);
        return PNULL;
	}
}

__IFN PIO_Stream* sopen_dir(const char* path) {
	if (!path) return PNULL;

    PIO_Stream* pio = (PIO_Stream*)zalloc(sizeof(PIO_Stream));
    if (!pio) return PNULL;

	#if defined(_WIN32)
		pio->stream.buf = (u8*)zalloc(sizeof(WIN32_FIND_DATAA));
		if (!pio->stream.buf) {
			pio->stream.md_err = PIO_ERR_OPEN;
            pio->last_err_xstr = "Failed to allocate memory";
			pio->last_err_func = "sopen_dir";
            
			goto error;
		}
		pio->stream.len = sizeof(WIN32_FIND_DATAA);
		pio->stream.cap = sizeof(WIN32_FIND_DATAA);
        pio->stream.handle = (uptr_t)INVALID_HANDLE_VALUE;
    #else
        DIR* fd = opendir(path);
        if (!fd) {
			pio->stream.md_err = PIO_ERR_OPEN;
            pio->last_err_xstr = "'opendir' returned NULL";
			pio->last_err_func = "sopen_dir";
            
			goto error;
        }
        pio->stream.handle = (uptr_t)fd;
    #endif

    pio->last_err_xstr = PNULL;
	pio->last_err_func = PNULL;
	pio->stream.md_err = PIO_ERR_NONE;
    pio->stream.filepos = 0;
	pio->stream.sfilepos = 0;
	pio->stream.spos = 0;
    pio->stream.flags = PSTREAM_FLAG_NONE;
	pio->stream.type = PSTREAM_TYPE_DIR;

	return pio;

	error: {
		if (pio->stream.buf) dealloc(pio->stream.buf);
		dealloc(pio);
        return PNULL;
	}
}

__IFN PIO_Stream* sopen_string(char* str, usize_t size, PStreamFlags flags) {
	if (!str || size < 1) return PNULL;

	PIO_Stream* pio = (PIO_Stream*)zalloc(sizeof(PIO_Stream));
    if (!pio) return PNULL;

	pio->last_err_xstr = PNULL;
	pio->last_err_func = PNULL;
	pio->stream.md_err = PIO_ERR_NONE;
    pio->stream.filepos = 0;
	pio->stream.sfilepos = 0;
	pio->stream.spos = 0;
    pio->stream.len = 0;
    pio->stream.flags = flags;
	pio->stream.type = PSTREAM_TYPE_STRING;
    pio->stream.buf = (u8*)str;
	pio->stream.len = size;
	pio->stream.cap = size;

	pio->string_md.string_size = size;
	pio->string_md.valid = true;
	return pio;
}

__IFN bool sclose(PIO_Stream* pio) {
    if (!pio) return false;

	switch (pio->stream.type) {
		case PSTREAM_TYPE_FILE: {
			#if defined(_WIN32)
				if (!CloseHandle((HANDLE)pio->stream.handle)) {
					pio->stream.md_err = PIO_ERR_CLOSE;
					pio->last_err_xstr = "'CloseHandle' returned FALSE (failure)";
					pio->last_err_func = "sclose";
					return false;
				}
			#else
				if (close((int)pio->stream.handle) < 0) {
					pio->stream.md_err = PIO_ERR_CLOSE;
					pio->last_err_xstr = "'close' returned negative value (failure)";
					pio->last_err_func = "sclose";
					return false;
				}
			#endif
			break;
		}

		case PSTREAM_TYPE_DIR: {
			#if defined(_WIN32)
				if (!FindClose((HANDLE)pio->stream.handle)) {
					pio->stream.md_err = PIO_ERR_CLOSE;
					pio->last_err_xstr = "'FindClose' returned FALSE (failure)";
					pio->last_err_func = "sclose";
					return false;
				}
			#else
				if (closedir((DIR*)pio->stream.handle) < 0) {
					pio->stream.md_err = PIO_ERR_CLOSE;
					pio->last_err_xstr = "'close' returned negative value (failure)";
					pio->last_err_func = "sclose";
					return false;
				}
			#endif
			break;
		}

		case PSTREAM_TYPE_STRING: {
			dealloc(pio);
			return true; // Internal buffer is directly binded to user specified string
		}

		default: {
			pio->stream.md_err = PIO_ERR_CLOSE;
            pio->last_err_xstr = "Unknown stream type";
			pio->last_err_func = "sclose";
			return false;
		}
	}

    if (pio->stream.buf) dealloc(pio->stream.buf);
    dealloc(pio);

	return true;
}

static bool i_sseek(PIO_Stream* pio, len_t offset, int origin, bool only_sys) {
    if (!pio) return false;
	
	switch(pio->stream.type) {
		case PSTREAM_TYPE_FILE: {
			if (only_sys) goto syscall;

			if (!pio->file_md.valid) {
				if (!sfile_md(PNULL, &pio->file_md, pio)) {
					pio->stream.md_err = PIO_ERR_MD; // Warning Error
					pio->last_err_xstr = "Failed to retrieve file metadata, using system call as a fallback";
					pio->last_err_func = "sseek";
					goto syscall; // Do not let the function fail just because of this
				}
			}

			// Check 2
			if (pio->file_md.valid) {
				switch (origin) {
					case SEEK_SET: {
						if (offset > (len_t)pio->file_md.file_size) {
							pio->stream.md_err = PIO_ERR_SEEK;
							pio->last_err_xstr = "Out-of-file Seek attempt";
							pio->last_err_func = "sseek";
							return false;
						}
						pio->stream.filepos = offset;
						return true;
					}
					case SEEK_CUR: {
						if (offset > 0 && pio->stream.filepos > (len_t)(INT64_MAX - offset)) {
							file_seek_cur_err: {
								pio->stream.md_err = PIO_ERR_SEEK;
								pio->last_err_xstr = "Out-of-file Seek attempt";
								pio->last_err_func = "sseek";
								return false;
							}
						}
						if (offset < 0 && pio->stream.filepos < (len_t)(INT64_MIN - offset)) goto file_seek_cur_err;

						pio->stream.filepos = offset + pio->stream.filepos;
						return true;
					}
					case SEEK_END: {
						if (offset > 0 && (len_t)pio->file_md.file_size > (len_t)(INT64_MAX - offset)) {
							file_seek_end_err: {
								pio->stream.md_err = PIO_ERR_SEEK;
								pio->last_err_xstr = "Out-of-file Seek attempt";
								pio->last_err_func = "sseek";
								return false;
							}
						}
						if (offset < 0 && (len_t)pio->file_md.file_size < (len_t)(INT64_MIN - offset)) goto file_seek_end_err;

						pio->stream.filepos = offset + pio->file_md.file_size;
						return true;
					}

					default: {
						pio->stream.md_err = PIO_ERR_SEEK;
						pio->last_err_xstr = "Invalid 'origin' value";
						pio->last_err_func = "sseek";
						return false;
					}
				}
			}

			syscall: {}

			#if defined(_WIN32)
				LARGE_INTEGER distance;
				LARGE_INTEGER new_pos;
				distance.QuadPart = offset;

				if (!SetFilePointerEx((HANDLE)pio->stream.handle, distance, &new_pos, origin)) {
					pio->stream.md_err = PIO_ERR_SEEK;
					pio->last_err_xstr = "'SetFilePointerEx' failed";
					pio->last_err_func = "sseek";
					return false;
				}

				pio->stream.sfilepos = (uoff_t)new_pos.QuadPart;
				pio->stream.filepos = pio->stream.sfilepos;
			#else
				long ret = lseek((int)pio->stream.handle, offset, origin);
				if (ret < 0) {
					pio->stream.md_err = PIO_ERR_SEEK;
					pio->last_err_xstr = "'lseek' returned negative value";
					pio->last_err_func = "sseek";
					return false;
				}

				pio->stream.sfilepos = (len_t)ret;
				pio->stream.filepos = pio->stream.sfilepos;
			#endif
			break;
		}

		case PSTREAM_TYPE_STRING: {
			switch (origin) {
				case SEEK_SET: {
					if (offset < 0 || offset > (len_t)pio->stream.len) {
						pio->stream.md_err = PIO_ERR_SEEK;
						pio->last_err_xstr = "Out-of-string Seek attempt";
						pio->last_err_func = "sseek";
						return false;
					}
					pio->stream.filepos = offset;
					break;
				}
				case SEEK_CUR: {
					if (offset > 0 && (len_t)pio->stream.filepos > (len_t)(INT64_MAX - offset)) {
						string_seek_cur_err: {
							pio->stream.md_err = PIO_ERR_SEEK;
							pio->last_err_xstr = "Out-of-string Seek attempt";
							pio->last_err_func = "sseek";
							return false;
						}
					}
					if (offset < 0 && (len_t)pio->stream.filepos < (len_t)(INT64_MIN - offset)) goto string_seek_cur_err;

					len_t fpos = offset + (len_t)pio->stream.filepos;
					if (fpos < 0 || fpos > (len_t)pio->stream.len) goto string_seek_cur_err;

					pio->stream.filepos = fpos;
					break;
				}
				case SEEK_END: {
					if (offset > 0 && (len_t)pio->stream.len > (len_t)(INT64_MAX - offset)) {
						string_seek_end_err: {
							pio->stream.md_err = PIO_ERR_SEEK;
							pio->last_err_xstr = "Out-of-file Seek attempt";
							pio->last_err_func = "sseek";
							return false;
						}
					}
					if (offset < 0 && (len_t)pio->stream.len < (len_t)(INT64_MIN - offset)) goto string_seek_end_err;
					
					len_t fpos = offset + (len_t)pio->stream.len;
					if (fpos < 0 || fpos > (len_t)pio->stream.len) goto string_seek_end_err;

					pio->stream.filepos = fpos;
					break;
				}

				default: {
					pio->stream.md_err = PIO_ERR_SEEK;
					pio->last_err_xstr = "Invalid 'origin' value";
					pio->last_err_func = "sseek";
					return false;
				}
			}

			pio->stream.sfilepos = pio->stream.filepos;
			return true;
		}

		default: {
			pio->stream.md_err = PIO_ERR_SEEK;
			pio->last_err_xstr = "Attempt to seek on a stream type that doesn't support seek";
			pio->last_err_func = "sseek";
			return false;
		}
	}

	return true;
}

static bool i_sbuf_init(PIO_Stream* pio) {
    if (!pio) return false;
    if (pio->stream.buf) return true;

    pio->stream.buf = (u8*)zalloc(PSTREAM_BUF_CHUNK_SIZE);
    if (!pio->stream.buf) return false;

    pio->stream.cap = PSTREAM_BUF_CHUNK_SIZE;
    pio->stream.len = 0;
    pio->stream.spos = (ulen_t)pio->stream.filepos;
    return true;
}

static usize_t i_sbuf_read(PIO_Stream* pio, void* buffer, usize_t size) {
    if (!pio || !buffer || !size) return 0;

    if (!i_sbuf_init(pio)) return 0;
    if (!pio->stream.buf || pio->stream.filepos < (len_t)pio->stream.spos) return 0;

    ulen_t offset = (ulen_t)(pio->stream.filepos - (len_t)pio->stream.spos);
    if (offset >= pio->stream.len) return 0;

    usize_t available = pio->stream.len - offset;
    usize_t amount = min(available, size);

    copybuf(buffer, pio->stream.buf + offset, amount);
    pio->stream.filepos += amount;
    return amount;
}

__IFN usize_t sread(PIO_Stream* pio, void* buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

	switch (pio->stream.type) {
		case PSTREAM_TYPE_FILE: {
			if (!pio->stream.buf) i_sbuf_init(pio);
			if (!pio->stream.buf) goto syscall;

			usize_t bytes_read = i_sbuf_read(pio, buffer, size);
			if (bytes_read < 1) goto syscall;
			else return bytes_read;

			syscall: {}
			if (pio->stream.filepos != pio->stream.sfilepos) {
				if (!i_sseek(pio, pio->stream.filepos, SEEK_SET, true)) return 0; // Error already created
			}

			bool buf_needed = pio->stream.buf && (size < pio->stream.cap);
			void* b = buf_needed ? pio->stream.buf : buffer; // Why should we even buffer this?
			usize_t sz = buf_needed ? pio->stream.cap : size;

			usize_t received = 0;
			#if defined(_WIN32)
				DWORD read = 0;
				if (!ReadFile((HANDLE)pio->stream.handle, b, (DWORD)sz, &read, PNULL)) {
					pio->stream.md_err = PIO_ERR_READ;
					pio->last_err_xstr = "'ReadFile' failed";
					pio->last_err_func = "sread";
					return 0;
				}

				received = (usize_t)read;
			#else
				long ret = read((int)pio->stream.handle, b, sz);
				if (ret < 0) {
					pio->stream.md_err = PIO_ERR_READ;
					pio->last_err_xstr = "'read' returned negative value";
					pio->last_err_func = "sread";
					return 0;
				}

				received = (usize_t)ret;
			#endif

			if (buf_needed) {
				usize_t delivered = min(size, received);

				pio->stream.spos = pio->stream.sfilepos + delivered;
				pio->stream.len = received - delivered; // If anything left dude....
				copybuf(buffer, pio->stream.buf, delivered);

				pio->stream.filepos += delivered;
				pio->stream.sfilepos += received;
				return delivered;
			}

			pio->stream.filepos += received;
			pio->stream.sfilepos += received;
			return received;
		}

		case PSTREAM_TYPE_STRING: {
			if (!(pio->stream.flags & PSTREAM_FLAG_READ)) {
				pio->stream.md_err = PIO_ERR_READ;
				pio->last_err_xstr = "String Stream doesn't support reading";
				pio->last_err_func = "sread";
				return 0;
			}

			if (!pio->stream.buf) {
				pio->stream.md_err = PIO_ERR_READ;
				pio->last_err_xstr = "String Stream doesn't have a destination string";
				pio->last_err_func = "sread";
				return 0;
			}

			if (pio->stream.sfilepos < 0 || pio->stream.sfilepos > (len_t)pio->stream.len) {
				pio->stream.md_err = PIO_ERR_READ;
				pio->last_err_xstr = "Out-of-string read attempt";
				pio->last_err_func = "sread";
				return 0;
			}

			usize_t to_read = min(pio->stream.len - pio->stream.sfilepos, size);
			copybuf(buffer, (const void*)(pio->stream.buf + pio->stream.sfilepos), to_read);

			pio->stream.filepos += to_read;
			pio->stream.sfilepos += to_read;
			return to_read;
		}

		default: {
			pio->stream.md_err = PIO_ERR_READ;
			pio->last_err_xstr = "Invalid Stream Type";
			pio->last_err_func = "sread";
			return 0;
		}
	}

	return 0;
}

__IFN char sgetc(PIO_Stream* pio) {
	if (!pio) return '\0';
	
	char out = '\0';
	usize_t bytes = sread(pio, &out, 1);
	if (bytes != 1) return out; // Would already send error

	return out;
}

__IFN void sungetc(PIO_Stream* pio) {
	if (!pio) return;
	if (pio->stream.filepos == 0) return;
	pio->stream.filepos--;
}

__IFN usize_t swrite(PIO_Stream* pio, const void* buffer, usize_t size) {
    if (!pio || !buffer || size == 0) return 0;

	if (pio->stream.filepos != pio->stream.sfilepos) {
		if (!i_sseek(pio, pio->stream.filepos, SEEK_SET, true)) return 0; // Error already created
	}

	switch (pio->stream.type) {
		case PSTREAM_TYPE_FILE: {
			#if defined(_WIN32)
				DWORD written = 0;
				if (!WriteFile((HANDLE)pio->stream.handle, buffer, (DWORD)size, &written, PNULL)) {
					if (GetLastError() == ERROR_IO_PENDING) goto success;
					pio->stream.md_err = PIO_ERR_WRITE;
					pio->last_err_xstr = "'WriteFile' failed";
					pio->last_err_func = "swrite";
					return 0;
				}
				
				success: {
					pio->file_md.valid = false;
					pio->stream.filepos += (usize_t)written;
					pio->stream.sfilepos += (usize_t)written;
					return (usize_t)written;
				}
			#else
				long ret = write((int)pio->stream.handle, buffer, size);
				if (ret < 0) {
					pio->stream.md_err = PIO_ERR_WRITE;
					pio->last_err_xstr = "'write' returned negative value";
					pio->last_err_func = "swrite";
					return 0;
				}
				
				pio->file_md.valid = false;
				pio->stream.filepos += (usize_t)ret;
				pio->stream.sfilepos += (usize_t)ret;
				return (usize_t)ret;
			#endif

			break;
		}

		case PSTREAM_TYPE_STRING: {
			if (!(pio->stream.flags & PSTREAM_FLAG_WRITE)) {
				pio->stream.md_err = PIO_ERR_WRITE;
				pio->last_err_xstr = "String Stream doesn't support writing";
				pio->last_err_func = "swrite";
				return 0;
			}

			if (!pio->stream.buf) {
				pio->stream.md_err = PIO_ERR_WRITE;
				pio->last_err_xstr = "String Stream doesn't have a destination string";
				pio->last_err_func = "swrite";
				return 0;
			}

			if (pio->stream.sfilepos < 0 || pio->stream.sfilepos > (len_t)pio->stream.len) {
				pio->stream.md_err = PIO_ERR_WRITE;
				pio->last_err_xstr = "Out-of-string write attempt";
				pio->last_err_func = "swrite";
				return 0;
			}

			usize_t to_write = min(pio->stream.len - pio->stream.sfilepos, size);
			copybuf((void*)(pio->stream.buf + pio->stream.sfilepos), buffer, to_write);

			pio->stream.filepos += to_write;
			pio->stream.sfilepos += to_write;
			return to_write;
		}

		default: {
			pio->stream.md_err = PIO_ERR_WRITE;
			pio->last_err_xstr = "Invalid Stream Type";
			pio->last_err_func = "swrite";
			return 0;
		}

	}
}

__IFN bool sseek(PIO_Stream* pio, len_t offset, int origin) {
	if (!pio) return false;
	return i_sseek(pio, offset, origin, false);
}

__IFN len_t stell(PIO_Stream* pio) {
    if (!pio) return (len_t)-1;
	return pio->stream.filepos;
}

__IFN bool seof(PIO_Stream* pio) {
    if (!pio) return true; // Count errors as EOF

	switch (pio->stream.type) {
		case PSTREAM_TYPE_FILE: {
			if (pio->stream.filepos < 0) return true;
			if (!pio->file_md.valid) {
				if (!sfile_md(PNULL, &pio->file_md, pio)) {
					pio->stream.md_err = PIO_ERR_MD;
					pio->last_err_xstr = "Failed to retrieve file metadata";
					pio->last_err_func = "seof";
					return true; // Count as EOF
				}
			}
			
			if (pio->stream.filepos >= (len_t)pio->file_md.file_size) return true;
			break;
		}

		case PSTREAM_TYPE_STRING: {
			if (pio->stream.filepos < 0) return true;
			if (pio->stream.filepos >= (len_t)pio->stream.len) return true;
			break;
		}

		default: break;
	}

	return false;
}

__IFN bool sflush(PIO_Stream* pio) {
	// TODO: Implement
	(void)pio;
	return true;
}

__IFN PIO_Errors slast_err(PIO_Stream* pio) {
    if (!pio) return PIO_ERR_UNK;
    return pio->stream.md_err;
}

__IFN const char* slast_err_msg(PIO_Stream* pio) {
    PIO_Errors err = slast_err(pio);

	switch (err) {
        case PIO_ERR_NONE: return "No error";
        case PIO_ERR_UNK: return "Unknown reason";
        case PIO_ERR_EOF: return "End of File (EOF)";
        case PIO_ERR_OPEN: return "Stream could not be opened";
		case PIO_ERR_CLOSE: return "Stream could not be closed";
        case PIO_ERR_READ: return "Stream could not be read from";
        case PIO_ERR_WRITE: return "Stream could not be written to";
        case PIO_ERR_SEEK: return "Stream seek failed";
		case PIO_ERR_MD: return "Stream Metadata load failed";
        default: return "Unknown reason";
    }
}

__IFN const char* slast_xerr_msg(PIO_Stream* pio, const char** xmsg, const char** func) {
	const char* out = slast_err_msg(pio);
	if (!pio) return out;

	if (xmsg) *xmsg = pio->last_err_xstr;
	if (func) *func = pio->last_err_func;
	return out;
}

__IFN int print(const char* str, usize_t size) {
    if (!str) return -1;
	if (size < 1) return 0;

    #if defined(_WIN32)
        if (PStdoutStream->stream.handle == INVALID_HANDLE_VALUE) return -1;

        int chars_written;
        WriteConsole(PStdoutStream->stream.handle, str, size, &chars_written, PNULL);
        return chars_written;
    #else
        return swrite(PStdoutStream, str, size);
    #endif

    return -1;
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
				
				if (!s) s = "(invalid hex)";
				else {
					for (char* sptr = s; *sptr; sptr++) {
						if (c_is_alpha(*sptr)) {
							*sptr = (*sptr & 0xDF);
						}
					}
				}

                if (base_prefix) {
                    written += swrite(pio, "0x", 2);
                }
                len_s = strlen(s);
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
                break;
            }
            case 'p': {
                uptr_t uint_v = (uptr_t)va_arg(ap, void*);
				s = u64_to_str((u64)uint_v, buf64, 16);
                if (!s) s = "(invalid pointer)";
                
				written += swrite(pio, "0x", 2);
                len_s = strlen(s);
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
                break;
            }
            case 'P': {
                uptr_t uint_v = (uptr_t)va_arg(ap, void*);
                s = u64_to_str((u64)uint_v, buf64, 16);
                
				if (!s) s = "(invalid pointer)";
                for (char* sptr = s; *sptr; sptr++) {
                    if (c_is_alpha(*sptr)) {
                        *sptr = (*sptr & 0xDF);
                    }
                }
               
				written += swrite(pio, "0x", 2);
                len_s = strlen(s);
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
                written += swrite(pio, s, len_s > precision_of_v && width_of_v > 0 ? precision_of_v : len_s);
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
	if (!pio || !format) return -1;

    va_list ap;
    start_va(ap, format);
    int ret = vfprints(pio, format, ap);
    end_va(ap);
    return ret;
}

__IFN int fmsprint(char* dst, usize_t max_size, const char* format, ...) {
	if (!dst || !format) return -1;
	if (max_size < 1) return 0;

	ulen_t sz = strlen(dst);
	ulen_t msz = min(sz, max_size);

	// Make fake PIO_Stream
	PIO_Stream pio = {
		.string_md.string_size = msz,
		.string_md.valid = true,

		.last_err_func = PNULL,
		.last_err_xstr = PNULL,

		.stream.buf = (u8*)dst,
		.stream.len = msz,
		.stream.cap = msz,
		.stream.type = PSTREAM_TYPE_STRING,
		.stream.md_err = PIO_ERR_NONE,
		.stream.flags = PSTREAM_FLAG_WRITE,
		.stream.filepos = 0,
		.stream.sfilepos = 0,
		.stream.spos = 0
	};

	va_list ap;
    start_va(ap, format);
    int ret = vfprints(&pio, format, ap);
    end_va(ap);
    return ret;
}

__IFN int fperror(const char* format, ...) {
	if (!format) return -1;

    va_list ap;
    start_va(ap, format);
    int ret = vfprints(s_stderr, format, ap);
    end_va(ap);

    const char* err = get_lasterr_msg();
    fprints(s_stderr, "\n    : %s\n", err);
    
    return ret;
}

