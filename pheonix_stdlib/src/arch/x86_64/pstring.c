// PString C Source file (for x86_64)
#define __IPSTDLIB_BUILD
#include <pstdlib.h>

__IFN bool copybuf(void* dest, const void* source, usize_t size) {
    if (!source || !dest) return false;
	if (size == 0) return true;

	__asm__ volatile(
		"cld\n\t"
		"rep movsb"
		:
		"+D"(dest), "+S"(source), "+c"(size)
		::
		"memory"
	);

	return (bool)(size == 0);
}

__IFN bool fillbuf(void* buf, byte_t value, usize_t size) {
    if (!buf) return false;
	if (size == 0) return true;

	usize_t remaining = size;
	void* ptr = buf;
	if (size >= 8) {
		usize_t size = remaining / 8;
		
		u8 byte = (u8)value;
		u64 pattern = 0x0101010101010101ULL * byte;

		__asm__ volatile(
			"cld\n\t"
			"rep stosq"
			::
			"D"(ptr), "c"(size), "a"((u64)pattern)
			:
			"memory"
		);
		remaining -= size * 8;
		ptr = (void*)((u8*)ptr + size * 8);
	}
    __asm__ volatile(
		"cld\n\t"
        "rep stosb"
        :
		"+D"(ptr), "+c"(remaining)
		:
		"a"((u8)value)
        :
		"memory"
    );

	return (bool)(remaining == 0);
}

__IFN bool movebuf(void* dest, const void* source, usize_t size) {
    if (!dest || !source) return false;
	if (size == 0) return true;

	u8* d = dest;
	const u8* s = source;

	if (d < s) {
		// Normal Copy
		return copybuf(dest, source, size);
	}

	// Backwards Copy
	d += size - 1;
    s += size - 1;
	__asm__ volatile(
		"std\n\t"
		"rep movsb\n\t"
		"cld"
		:
		"+D"(d), "+S"(s), "+c"(size)
		::
		"memory"
	);

	return (bool)(size == 0);
}

__IFN int cmpbuf(const void* a, const void* b, usize_t size) {
	if (!a || !b) return INT_MIN;
	if (size == 0) return 0;

    int res = 0;
	__asm__ volatile(
        "cld\n\t"
        "repe cmpsb\n\t"
        "je 1f\n\t"
        "movzbl -1(%%rsi), %%eax\n\t"
        "movzbl -1(%%rdi), %%edx\n\t"
        "sub %%edx, %%eax\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "xor %%eax, %%eax\n"
        "2:"
        :
		"=a"(res), "+S"(a), "+D"(b), "+c"(size)
        ::
		"rdx", "memory", "cc"
    );

	return res;
}

__IFN usize_t strlen(const char* str) {
	if (!str) return 0;

    usize_t len;

    __asm__ volatile(
        "cld\n\t"
        "xor %%eax, %%eax\n\t"
        "mov $-1, %%rcx\n\t"
        "repne scasb\n\t"
        "not %%rcx\n\t"
        "dec %%rcx"
        :
		"=c"(len), "+D"(str)
        ::
		"rax", "memory", "cc"
    );

    return len;
}

/*
! Function is not yet complete for use

__IFN const char* strfindc(const char* str, char c, usize_t occurrence) {
	if (!str) return PNULL;

	while ((uptr_t)str & 0xF) {
        if (!*str) return NULL;
        if (*str == c) {
            if (occurrence == 0) return str;
            occurrence--;
        }
        str++;
    }

    const char* res = PNULL;
	__asm__ volatile(
		// make sure xmm1 contains the search character in every byte
		"movd %[c], %%xmm1\n\t"
		"punpcklbw %%xmm1, %xmm1\n\t"
		"punpcklwd %%xmm1, %xmm1\n\t"
		"pshufd $0, %%xmm1, %%xmm1\n\t"
        "pxor %%xmm2, %%xmm2\n\t"

        "1:\n\t"
		// Load and compare 16 bytes at once
        "movdqa (%[str]), %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm3\n\t"
        "pcmpeqb %%xmm1, %%xmm3\n\t"
        "pmovmskb %%xmm3, %%eax\n\t"

		// Check for NULL terminator
        "pcmpeqb %%xmm2, %%xmm0\n\t"
        "pmovmskb %%xmm0, %%edx\n\t"
        "test %%edx, %%edx\n\t"
        "jz 2f\n\t"

		// Enumerate matches
        "bsf %%edx, %%ecx\n\t"
        "mov $1, %%edx\n\t"
        "shl %%cl, %%edx\n\t"
        "dec %%edx\n\t"
        "and %%edx, %%eax\n\t"

        "2:\n\t"
        "test %%eax, %%eax\n\t"
        "jz 4f\n\t"
		
        "3:\n\t"
        "bsf %%eax, %%ecx\n\t"
        "test %[occ], %[occ]\n\t"
        "jz 5f\n\t"
        "dec %[occ]\n\t"
        "lea -1(%%eax), %%edx\n\t"
        "and %%edx, %%eax\n\t"
        "jnz 3b\n\t"

        "4:\n\t"
        "test %%edx, %%edx\n\t"
        "jnz 6f\n\t"
        "add $16, %[str]\n\t"
        "jmp 1b\n\t"

        "5:\n\t"
		// Found it
        "lea (%[str],%%rcx), %[res]\n\t"
        "jmp 6f\n\t"

        "6:\n\t"
        :
		[str] "+r" (str), [occ] "+r" (occurrence), [res] "=r" (res)
        :
		[c] "r" ((u32)(u8)c)
        :
		"rax", "rdx", "rcx", "xmm0", "xmm1", "xmm2", "xmm3", "cc", "memory"
	);

	return res;
}
*/

__IFN const char* strfindc(const char* str, char c, psize_t occurrence) {
	if (!str) return PNULL;

    usize_t n = strlen(str);
    usize_t coccur = 0;

	const char* last_occur = PNULL;
    const char* cstr = str;

    for (usize_t i = 0; i < n; i++) {
        cstr = (const char*)(str + i);
        if (str[i] == c) {
			last_occur = cstr;
            coccur++;

			if (occurrence < 0) continue;

            if ((usize_t)occurrence == 0 || coccur == (usize_t)occurrence) {
                return cstr;
            }
        }
    }

	if (occurrence < 0) return last_occur;
    return PNULL;
}
