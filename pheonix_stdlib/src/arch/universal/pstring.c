// PString C Source file (Universal)
// TODO: Fix all compatibility problems in functions

#define __IPSTDLIB_BUILD
#include <pstdlib.h>

__IFN bool copybuf(void* dest, const void* source, usize_t size) {
    if (size == 0) return true;
    else if (!source || !dest) return false;

    byte_t* dst = (byte_t*)dest;
    byte_t* src = (byte_t*)source;

    if (size < 32) {
        for (usize_t i = 0; i < size; i++)
            dst[i] = src[i];
        return true;
    }

    uptr_t p = ((uptr_t)dst) & (sizeof(u64) - 1);
    usize_t i = 0;
    if (p) {
        uptr_t to_align = (sizeof(u64) - p) & (sizeof(u64) - 1);
        if (to_align > size)
            to_align = size;
        for (; i < to_align; i++)
            dst[i] = src[i];
    }

    usize_t remain = size - i;
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

    for (; i < size; i++)
        dst[i] = src[i];
    return true;
}

__IFN bool fillbuf(void* buf, byte_t value, usize_t size) {
    if (size == 0) return true;
    else if (!buf) return false;

    byte_t* dest = (byte_t*)buf;

    if (size < 32) {
        for (usize_t i = 0; i < size; i++)
            dest[i] = value;
        return true;
    }

    uptr_t p = ((uptr_t)dest) & (sizeof(u64) - 1);
    usize_t i = 0;
    if (p) {
        uptr_t to_align = (sizeof(u64) - p) & (sizeof(u64) - 1);
        if (to_align > size)
            to_align = size;
        for (; i < to_align; i++)
            dest[i] = value;
    }

    usize_t remain = size - i;
    if (remain >= sizeof(u64)) {
        u64 pat = (u64)value * (u64)0x0101010101010101ULL;
        u64* wd = (u64*)(dest + i);
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

    for (; i < size; i++)
        dest[i] = value;
    return true;
}

// TODO: Fix
__IFN bool movebuf(void* dest, const void* source, usize_t size) {
	if (!dest || !source) return false;
	if (size == 0) return true;

    if (!copybuf(dest, source, size)) return false;
    return fillbuf(source, 0, size);
}

__IFN int cmpbuf(const void* a, const void* b, usize_t size) {
	if (!a || !b) return INT_MIN;
	if (size == 0) return 0;

    byte_t* x = a;
    byte_t* y = b;

    for (usize_t i = 0; i < size; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

__IFN usize_t strlen(const char* str) {
	if (!str) return 0;
	
    const char* s = str;
    while (*s) s++;
    return s - str;
}