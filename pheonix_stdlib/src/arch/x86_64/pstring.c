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

	size_t remaining = size;
	void* ptr = buf;
	if (size >= 8) {
		size_t size = remaining / 8;
		
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

    size_t len;

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
