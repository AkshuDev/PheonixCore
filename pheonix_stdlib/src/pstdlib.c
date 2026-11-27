// PStdlib C Source file

#define __IPSTDLIB_BUILD
#include <pstdlib.h>

#if defined(__linux__)
    #include <sys/mman.h>
#elif defined(_WIN32)
	#include <windows.h>
	#include <sysinfoapi.h>
    #include <memoryapi.h>
    #include <winnt.h>
#endif

static char** env_vars = PNULL;
static size_t env_count = 0;

static void** exalloc_ptrs = PNULL;
static usize_t exalloc_capacity = 0;
static usize_t exalloc_count = 0;
static usize_t* exalloc_free_stack = PNULL;
static usize_t exalloc_free_count = 0;

static struct PEHdlr* exit_handlers = PNULL;

__IFN llong_t __plib_syscall(int id, ...) {
    llong_t ret = 0;
    llong_t args[6] = {0};

    va_list ap;
    start_va(ap, id);
    for (int i = 0; i < 6; i++) args[i] = va_arg(ap, llong_t);
    end_va(ap);

	#if __PARCH__ == x86_64
		#if defined(__linux__) || defined(__unix__)
			long raw;

			register long r10 asm("r10") = (long)args[3];
			register long r8 asm("r8") = (long)args[4];
			register long r9 asm("r9") = (long)args[5];

			__asm__ volatile (
				"syscall"
				: "=a"(raw)
				: "0"((long)id), "D"((long)args[0]), "S"((long)args[1]), "d"((long)args[2]), "r"(r10), "r"(r8), "r"(r9)
				: "rcx", "r11", "memory", "cc"
			);

			ret = (llong_t)raw;
		#endif
	#elif __PARCH__ == x86
		#if defined(__linux__) || defined(__unix__)
			int raw;

			register int ebx asm("ebx") = (int)args[0];
			register int ecx asm("ecx") = (int)args[1];
			register int edx asm("edx") = (int)args[2];
			register int esi asm("esi") = (int)args[3];
			register int edi asm("edi") = (int)args[4];
			register int ebp asm("ebp") = (int)args[5];

			__asm__ volatile (
				"int $0x80"
				: "=a"(raw)
				: "0"(id), "b"(ebx), "c"(ecx), "d"(edx), "S"(esi), "D"(edi), "r"(ebp)
				: "memory", "cc"
			);

			ret = (llong_t)raw;
		#endif
	#elif __PARCH__ == arm64
		register long x0 asm("x0") = (long)args[0];
		register long x1 asm("x1") = (long)args[1];
		register long x2 asm("x2") = (long)args[2];
		register long x3 asm("x3") = (long)args[3];
		register long x4 asm("x4") = (long)args[4];
		register long x5 asm("x5") = (long)args[5];
		register long x8 asm("x8") = (long)id;

		__asm__ volatile (
			"svc 0"
			: "+r"(x0)
			: "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
			: "memory", "cc"
		);

		ret = (llong_t)x0;
	#elif __PARCH__ == arm32
		register long r0 asm("r0") = (long)args[0];
		register long r1 asm("r1") = (long)args[1];
		register long r2 asm("r2") = (long)args[2];
		register long r3 asm("r3") = (long)args[3];
		register long r4 asm("r4") = (long)args[4];
		register long r5 asm("r5") = (long)args[5];
		register long r7 asm("r7") = (long)id;

		__asm__ volatile (
			"svc 0"
			: "+r"(r0)
			: "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
			: "memory", "cc"
		);

		ret = (llong_t)r0;
	#else
		ret = -1;
	#endif

    return ret;
}

__IFN void __plib_reset_env(char** envp, usize_t envp_count) {
    env_vars = alloc(envp_count);
    if (env_vars) {
        copybuf(env_vars, envp, sizeof(char*) * envp_count);
    }
}

__IFN uoff_t findbyte(const void* search_area, byte_t byte, usize_t size) {
    // Not Yet implemented
	(void)search_area; (void)byte; (void)size;
	return 0;
}

__IFN void* exalloc(usize_t size, uint_t type, void* link, bool auto_free) {
    void* ptr = PNULL;
    uint_t prot = 0;

    #if defined(__linux__)
        if (type & ALLOC_MEMTYPE_EXEC)
            prot |= PROT_EXEC;
        if (type & ALLOC_MEMTYPE_NONE)
            prot |= PROT_NONE;
        if (type & ALLOC_MEMTYPE_READ)
            prot |= PROT_READ;
        if (type & ALLOC_MEMTYPE_WRITE)
            prot |= PROT_WRITE;
        ptr = mmap(PNULL, size + sizeof(struct PHM_Hdr), prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ptr == MAP_FAILED) {
            ptr = PNULL;
        }
    #elif defined(_WIN32)
        if (type & ALLOC_MEMTYPE_EXEC && type & ALLOC_MEMTYPE_READ &&
            type & ALLOC_MEMTYPE_WRITE)
            prot = PAGE_EXECUTE_READWRITE;
        else if (type & ALLOC_MEMTYPE_EXEC && type & ALLOC_MEMTYPE_READ)
            prot = PAGE_EXECUTE_READ 
        else if (type & ALLOC_MEMTYPE_EXEC) 
            prot = PAGE_EXECUTE;
        else if (type & ALLOC_MEMTYPE_NONE)
            prot = PAGE_NOACCESS;
        else if (type & ALLOC_MEMTYPE_WRITE)
            prot = PAGE_READWRITE;
        else if (type & ALLOC_MEMTYPE_READ)
            prot = PAGE_READONLY;
        else
            prot = PAGE_NOACCESS;

        ptr = VirtualAlloc(PNULL, size + sizeof(struct PHM_Hdr), MEM_COMMIT | MEM_RESERVE, prot);
	#elif defined(__AOS__)
		ptr = PNULL; // Not yet implemented
    #else
        ptr = PNULL;
    #endif
    
    if (!ptr) return PNULL;

    struct PHM_Hdr* hdr = (struct PHM_Hdr*)ptr;
    hdr->size = size;
    hdr->flags = auto_free ? __PHM_HDR_FLAG_AUTO_FREE__ | __PHM_HDR_FLAG_ALLOCATED__ : __PHM_HDR_FLAG_ALLOCATED__;
    hdr->auto_free_idx = 0;
    hdr->next_count = 0;
	hdr->root = hdr;
    
	if (link) {
		struct PHM_Hdr* lhdr = (struct PHM_Hdr*)((u8*)link - sizeof(struct PHM_Hdr));
        lhdr->next = hdr;
		hdr->root = lhdr->root ? lhdr->root : hdr;
		hdr->prev = lhdr;

		lhdr->next_count++;
	}

    void* rptr = (void*)((ubyte_t*)ptr + sizeof(struct PHM_Hdr));
    if (auto_free) {
        usize_t idx = 0;
        if (exalloc_free_count > 0) {
            idx = exalloc_free_stack[--exalloc_free_count];
        } else {
            if (exalloc_count >= exalloc_capacity) {
                usize_t newcap = exalloc_capacity ? exalloc_capacity * 2 : 16;
                
                void* nptr = exalloc(newcap * sizeof(void*), ALLOC_MEMTYPE_READ | ALLOC_MEMTYPE_WRITE, PNULL, false);
                if (!nptr) return rptr; // Cant auto free this
                copybuf(nptr, exalloc_ptrs, sizeof(void*) * exalloc_capacity);
                dealloc(exalloc_ptrs);
                exalloc_ptrs = nptr;

                nptr = exalloc(newcap * sizeof(usize_t), ALLOC_MEMTYPE_READ | ALLOC_MEMTYPE_WRITE, PNULL, false);
                if (!nptr) return rptr;
                copybuf(nptr, exalloc_free_stack, sizeof(usize_t) * exalloc_capacity);
                dealloc(exalloc_free_stack);
                exalloc_free_stack = nptr;

                exalloc_capacity = newcap;
            }

            idx = exalloc_count++;
        }

        exalloc_ptrs[idx] = rptr;

        hdr->auto_free_idx = idx;
    }

    return rptr;
}

__IFN void* alloc(usize_t size) {
    return exalloc(size, ALLOC_MEMTYPE_READ | ALLOC_MEMTYPE_WRITE, PNULL, true);
}

static void _dealloc(void* ptr, struct PHM_Hdr* hdr) {
    if (!hdr) return;

	if (hdr->next_count > 0 && hdr->next) _dealloc((void*)((u8*)hdr->next + sizeof(struct PHM_Hdr)), hdr->next);
    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__)) return; // DeAllocated Probably

    if (hdr->flags & __PHM_HDR_FLAG_AUTO_FREE__) {
        // Add a free slot
        if (exalloc_ptrs[hdr->auto_free_idx] == ptr) {
            exalloc_ptrs[hdr->auto_free_idx] = PNULL;
            if (exalloc_free_count < exalloc_capacity)
                exalloc_free_stack[exalloc_free_count++] = hdr->auto_free_idx;
        }
    }

    usize_t size = hdr->size + sizeof(struct PHM_Hdr);
    fillbuf(hdr, 0, sizeof(struct PHM_Hdr)); // Invalidate
    #if defined(__linux__)
        munmap((void* )hdr, size); // Hdr already points to the starting pos
    #elif defined(_WIN32)
        VirtualFree((void* )hdr, size, MEM_RELEASE);
    #endif
}

__IFN void dealloc(void* ptr) {
	if (!ptr) return;

	struct PHM_Hdr* hdr = (struct PHM_Hdr*)((u8*)ptr - sizeof(struct PHM_Hdr));
    if (hdr->root && hdr->root != hdr) _dealloc(ptr, hdr->root);
}

__IFN void* zalloc(usize_t size) {
    void* ptr = exalloc(size, ALLOC_MEMTYPE_READ | ALLOC_MEMTYPE_WRITE, PNULL, true);
    if (!ptr) return ptr;
    if (!fillbuf(ptr, 0, size)) {
        dealloc(ptr);
        return PNULL;
    }
    return ptr;
}

__IFN void* ralloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, ALLOC_MEMTYPE_WRITE | ALLOC_MEMTYPE_READ, PNULL, true);
    if (!nptr) {
        return PNULL;
    }
    struct PHM_Hdr* hdr = (struct PHM_Hdr*)((u8*)ptr - sizeof(struct PHM_Hdr));
    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__)) return PNULL; // Cant reallocate
    copybuf(nptr, ptr, hdr->size);

    dealloc(ptr);
    return nptr;
}

__IFN void* rzalloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, ALLOC_MEMTYPE_READ | ALLOC_MEMTYPE_WRITE, ptr, true);
    if (!nptr) {
        return PNULL;
    }
    if (!fillbuf(nptr, 0, size)) {
        dealloc(nptr);
        return PNULL;
    }

    struct PHM_Hdr* hdr = (struct PHM_Hdr*)((u8*)ptr - sizeof(struct PHM_Hdr));
    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__)) return PNULL; // Cant reallocate
    copybuf(nptr, ptr, hdr->size);

    dealloc(ptr);
    return nptr;
}

__IFN void* alignptr(void* ptr, usize_t alignment) {
    uptr_t addr = (uptr_t)ptr;
    return (void*)((addr + alignment - 1) & ~(alignment - 1));
}

__IFN void* alignbuf(void* buf, usize_t alignment) {
    return alignptr(buf, alignment);
}

__IFN bool isaligned(void* ptr, usize_t alignment) {
    return ((uptr_t)ptr % alignment) == 0;
}

__IFN usize_t alignup(usize_t val, usize_t alignment) {
    return (val + alignment - 1) & ~(alignment - 1);
}

__IFN usize_t aligndown(usize_t val, usize_t alignment) {
    return val & ~(alignment - 1);
}

__IFN bool strcopy(char* dest, const char* src) {
	if (!dest || !src) return false;

	usize_t n1 = strlen(src) + 1; // +NULL Terminator
	usize_t n2 = strlen(dest) + 1; // +NULL Terminator
    return copybuf(dest, src, min(n1, n2));
}

__IFN bool strscopy(char* dest, const char* src, usize_t size) {
	if (!dest || !src) return false;
	if (size == 0) return true;

    usize_t n1 = strlen(src) + 1; // +NULL Terminator
	usize_t n2 = strlen(dest) + 1; // +NULL Terminator
    return copybuf(dest, src, min(min(n1, n2), size));
}

__IFN int strcmp(const char* a, const char* b) {
	if (!a || !b) return false;

    usize_t n1 = strlen(a);
    usize_t n2 = strlen(b);
    
	int cmp = cmpbuf(a, b, min(n1, n2));
	if (cmp != 0) return cmp;
    return (n1 > n2) - (n1 < n2);
}

__IFN int strscmp(const char* a, const char* b, usize_t size) {
	if (!a || !b) return false;
	if (size == 0) return true;

    usize_t n1 = strlen(a);
    usize_t n2 = strlen(b);
	usize_t n = min(min(n1, n2), size);

    int cmp = cmpbuf(a, b, n);
    if (cmp != 0) return cmp;
	
    if (n == size) return 0;
    return (n1 > n2) - (n1 < n2);
}

__IFN char* strfindstr(const char* str, const char* substr, psize_t occurrence) {
	if (!str || !substr) return PNULL;

    usize_t n = strlen(str);
	usize_t sn = strlen(substr);
	if (sn > n || sn < 1) return PNULL; // Substring bigger than string, yeah ain't happening

    usize_t coccur = 0;
	const char* last_occur = PNULL;
    const char* cstr = str;

    for (usize_t i = 0; i <= n - sn; i++) {
        cstr = (const char*)(str + i);
        if (str[i] == substr[0]) {
			if (strncmp(cstr, substr, sn) != 0) continue;

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

__IFN char* strsplit(const char* str, char c, usize_t occurrence, bool first_part) {
	if (!str) return PNULL;

    usize_t n = strlen(str);
    usize_t coccur = 0;

    const char* cstr = str;

    for (usize_t i = 0; i < n; i++) {
        cstr = (char*)(str + i);
        if (str[i] == c) {
            coccur++;
            if (occurrence == 0 || coccur == occurrence) {
                usize_t s = first_part ? i + 2 : n - (i + 2);
                if (s == 0) return PNULL;
                char* split = alloc(s);
                if (!split) return PNULL;

                if (first_part) strscopy(split, cstr, s);
                else strscopy(split, str, s);
                return split;
            }
        }
    }
    return PNULL;
}

__IFN char* retenv(const char* name) {
    if (!env_vars || !name) return PNULL;

    usize_t len = strlen(name);
    for (size_t i = 0; i < env_count; i++) {
        char* e = env_vars[i];
        if (!e) continue;

        if (!strscmp(e, (char*)name, len) && e[len] == '=') {
            return e + len + 1;
        }
    }
    return PNULL;
}

__IFN bool assignenv(const char* name, const char* val, bool overwrite) {
    if (!env_vars || !name || !val) return false;

    usize_t nlen = strlen(name);
    usize_t vlen = strlen(val);

    // Search existing
    for (usize_t i = 0; i < env_count; i++) {
        char* e = env_vars[i];
        if (!e) continue;

        if (!strscmp(e, (char*)name, nlen) && e[nlen] == '=') {
            if (!overwrite)
                return true;

            // Replace existing
            usize_t len = nlen + 1 + vlen + 1;
            char* ne = alloc(len);
            if (!ne) return false;

            // build "name=value"
            copybuf(ne, name, nlen);
            ne[nlen] = '=';
            copybuf(ne + nlen + 1, val, vlen);
            ne[len - 1] = '\0';

            env_vars[i] = ne;
            return true;
        }
    }

    // Not found then append
    char** new_env = ralloc(env_vars, sizeof(char*) * (env_count + 1));
    if (!new_env) return false;

    env_vars = new_env;

    usize_t len = nlen + 1 + vlen + 1;
    char* ne = alloc(len);
    if (!ne) return false;

    copybuf(ne, name, nlen);
    ne[nlen] = '=';
    copybuf(ne + nlen + 1, val, vlen);
    ne[len - 1] = '\0';

    env_vars[env_count++] = ne;

    return true;
}

__IFN char* i64_to_str(i64 v, char* buf, int base) {
    char* p = buf;
    bool neg = false;

    u64 val;
    if (base == 10 && v < 0) {
        neg = true;
        val = (u64)(-(v + 1)) + 1;
    } else {
        val = (u64)v;
    }

    do {
        u64 digit = val % base;
        *p++ = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
        val /= base;
    } while (val);

    if (neg)
        *p++ = '-';

    *p = '\0';

    char* start = buf;
    char* end = p - 1;

    while (start < end) {
        char tmp = *start;
        *start++ = *end;
        *end-- = tmp;
    }

    return buf;
}

__IFN char* u64_to_str(u64 v, char* buf, int base) {
    char* p = buf;

    u64 val = (u64)v;

    do {
        u64 digit = val % base;
        *p++ = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
        val /= base;
    } while (val);

    *p = '\0';

    char* start = buf;
    char* end = p - 1;

    while (start < end) {
        char tmp = *start;
        *start++ = *end;
        *end-- = tmp;
    }

    return buf;
}

__IFN char* double_to_str(double v, char* buf, int precision) {
    if (!buf) return 0;

    if (precision < 0) precision = 6;

    char* p = buf;

    if (v < 0) {
        *p++ = '-';
        v = -v;
    }

    i64 int_part = (i64)v;
    double frac = v - (double)int_part;

    char tmp[32];
    char* t = tmp;

    do {
        *t++ = '0' + (int_part % 10);
        int_part /= 10;
    } while (int_part);

    while (t > tmp)
        *p++ = *--t;

    *p++ = '.';

    for (int i = 0; i < precision; i++) {
        frac *= 10.0;
        int digit = (int)frac;
        *p++ = '0' + digit;
        frac -= digit;
    }

    *p = 0;
    return buf;
}

__IFN int char_to_digit(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10;

    return -1;
}

__IFN u64 str_to_u64(const char* str, char** endptr, int base) {
	if (endptr) *endptr = (char*)str;
    if (!str || base < 2 || base > 36) return 0;

	while (*str && c_is_space(*str)) str++;
	if (!*str) return 0;

    u64 result = 0;
	bool converted = false;

    if (*str == '+') str++;
	if (base == 0) {
        if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
            base = 16;
            str += 2;
        } else if (str[0] == '0') {
            base = 8;
        } else if (str[0] == '0' && (str[1] == 'b' || str[1] == 'B')) {
			base = 2;
			str += 2;
		} else {
            base = 10;
        }
    } else if (base == 16 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }

    while (*str) {
        int digit = char_to_digit(*str);
        if (digit < 0 || digit >= base) break;

		converted = true;

        if (result > (UINT64_MAX - digit) / base) {
			while (*str) {
                int d = char_to_digit(*str);
                if (d < 0 || d >= base) break;
                str++;
            }

			if (endptr) *endptr = (char*)str;
            return UINT64_MAX;
        }

        result = result * base + digit;
        str++;
	}

	if (!converted) return 0; // endptr remains at start
	if (endptr) *endptr = (char*)str;
    return result;
}

__IFN s64 str_to_i64(const char* str, char** endptr, int base) {
	if (endptr) *endptr = (char*)str;
    if (!str || base < 2 || base > 36) return 0;

	while (*str && c_is_space(*str)) str++;
	if (!*str) return 0;

	bool neg = false;

    if (*str == '-') {
        neg = true;
        str++;
    } else if (*str == '+') {
        str++;
    }

	if (base == 0) {
        if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
            base = 16;
            str += 2;
        } else if (str[0] == '0') {
            base = 8;
        } else if (str[0] == '0' && (str[1] == 'b' || str[1] == 'B')) {
			base = 2;
			str += 2;
		} else {
            base = 10;
        }
    } else if (base == 16 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }

    u64 result = 0;
	u64 limit = neg ? (u64)INT64_MAX + 1 : (u64)INT64_MAX;
	bool converted = false;

    while (*str) {
        int digit = char_to_digit(*str);
        if (digit < 0 || digit >= base) break;

		converted = true;

        if (result > (limit - digit) / base) {
			while (*str) {
                int d = char_to_digit(*str);
                if (d < 0 || d >= base) break;
                str++;
            }

			if (endptr) *endptr = (char*)str;
            return neg ? INT64_MIN : INT64_MAX;
        }

        result = result * base + digit;
        str++;
    }

	if (!converted) return 0;
	if (endptr) *endptr = (char*)str;

    if (neg) {
        if (result == (u64)INT64_MAX + 1) return INT64_MIN;
        return -(s64)result;
    }

    return (s64)result;
}

__IFN double str_to_double(const char* str, char** endptr) {
	if (endptr) *endptr = (char*)str;
    if (!str) return 0.0;

	while (*str && c_is_space(*str)) str++;
	if (!*str) return 0.0;

    double result = 0.0;
    double frac = 0.0;
    double div = 1.0;
    int sign = 1;

    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') { str++; }

	bool converted = false;
    while (c_is_digit(*str)) {
		converted = true;
        result = result * 10.0 + (*str - '0');
        str++;
    }

    if (*str == '.') {
        str++;

        while (c_is_digit(*str)) {
			converted = true;

            frac = frac * 10.0 + (*str - '0');
            div *= 10.0;
            str++;
        }
        result += frac / div;
    }

	if (!converted) return 0.0;
	if (endptr) *endptr = (char*)str;
    return result * sign;
}

__IFN bool c_is_space(char c) {
	return (
		c == ' '  ||
        c == '\t' ||
        c == '\n' ||
        c == '\r' ||
        c == '\v' ||
        c == '\f'
	);
}

__IFN bool c_is_alpha(char c) {
    return ((c >= 'a' && c <= 'z') && (c >= 'A' && c <= 'Z'));
}

__IFN bool c_is_digit(char c) {
    return (c >= '0' && c <= '9');
}

__IFN bool c_is_alphanum(char c) {
    return c_is_alpha(c) || c_is_digit(c);
}

__IFN char c_to_lower(char c) {
	if (!c_is_alpha(c)) return c;
	return c | 0x20;
}

__IFN char c_to_upper(char c) {
	if (!c_is_alpha(c)) return c;
	return c & (~0x20);
}

__IFN bool is_space(const char* s) {
	if (!s || !*s) return false;
	
    for (const char* p = s; *p; p++) {
        if (!c_is_space(*p)) return false;
    }
    return true;
}

__IFN bool is_alpha(const char* s) {
	if (!s || !*s) return false;

    for (const char* p = s; *p; p++) {
        if (!c_is_alpha(*p)) return false;
    }
    return true;
}

__IFN bool is_digit(const char* s) {
	if (!s || !*s) return false;

    for (const char* p = s; *p; p++) {
        if (!c_is_digit(*p)) return false;
    }
    return true;
}

__IFN bool is_alphanum(const char* s) {
	if (!s || !*s) return false;

    for (const char* p = s; *p; p++) {
        if (!c_is_alphanum(*p)) return false;
    }
    return true;
}

__IFN bool is_float(const char* s) {
    if (!s || !*s) return false;

    bool has_digit = false;
    bool has_dot = false;

    if (*s == '+' || *s == '-') s++;

    while (*s) {
        if (c_is_digit(*s)) {
            has_digit = true;
        } else if (*s == '.' && !has_dot) {
            has_dot = true;
        } else {
            return false;
        }
        s++;
    }

    return has_digit;
}

__IFN bool to_lower(char* s){
	if (!s || !*s) return false;

	for (char* p = s; *p; p++) {
		char c = *p;
        *p = c_to_lower(c);
    }
	return true;
}

__IFN bool to_upper(char* s){
	if (!s || !*s) return false;

	for (char* p = s; *p; p++) {
		char c = *p;
        *p = c_to_upper(c);
    }
	return true;
}

__IFN timestamp_t time_unix(void) {
	#if defined(_WIN32)
		SYSTEMTIME t;
		FILETIME ft;

		GetSystemTime(&t);
		SystemTimeToFileTime(&t, &ft);

		ULARGE_INTEGER ticks;
    	ticks.LowPart = ft.dwLowDateTime;
    	ticks.HighPart = ft.dwHighDateTime;

		return (timestamp_t)((ticks.QuadPart / 10000000ULL) - TIME_UNIX_EPOCH);
	#elif defined(__linux__)
		struct timespec {
         	long int tv_sec;// seconds
            long tv_nsec; // nanoseconds
        };

		struct timespec ts = {0};
		#if __PARCH__ == x86_64
            if (__plib_syscall(228, 0LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == x86
            if (__plib_syscall(265, 0LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == arm32
            if (__plib_syscall(263, 0LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == arm64
            if (__plib_syscall(113, 0LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #endif

		return (timestamp_t)ts.tv_sec;
	#else
		#error Unsupported platform
	#endif
}

__IFN nstime_t time_ns(void) {
	#if defined(_WIN32)
		LARGE_INTEGER t;
		LARGE_INTEGER f;
		if (!QueryPerformanceCounter(&t)) return 0;
		if (!QueryPerformanceFrequency(&f)) return 0;

		uint64_t ticks = (uint64_t)t.QuadPart;
    	uint64_t freq = (uint64_t)f.QuadPart;
		uint64_t seconds = ticks / freq;
    	uint64_t remainder = ticks % freq;

		return (nstime_t)((seconds * 1000000000ULL) + ((remainder * 1000000000ULL) / freq));
	#elif defined(__linux__)
		struct timespec {
         	long int tv_sec;// seconds
            long tv_nsec; // nanoseconds
        };

		struct timespec ts = {0};
		#if __PARCH__ == x86_64
            if (__plib_syscall(228, 1LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == x86
            if (__plib_syscall(265, 1LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == arm32
            if (__plib_syscall(263, 1LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #elif __PARCH__ == arm64
            if (__plib_syscall(113, 1LL, (llong_t)(uptr_t)&ts, 0, 0, 0, 0) < 0) return 0;
        #endif

		return (nstime_t)((ts.tv_sec * 1000000000LL) + ts.tv_nsec);
	#else
		#error Unsupported platform
	#endif
}

__IFN ustime_t time_us(void) {
	return (ustime_t)(time_ns() / 1000);
}

__IFN mstime_t time_ms(void) {
	return (mstime_t)(time_ns() / 1000000);
}

__IFN stime_t time_s(void) {
	return (stime_t)(time_ns() / 1000000000);
}

__IFN i64 append_i64(i64 a, i64 b) {
    if (b == 0) return a * 10;

    i64 tmp = b;
    i64 mult = 1;

    while (tmp > 0) {
        mult *= 10;
        tmp /= 10;
    }

    return a * mult + b;
}

__IFN bool aexitf(void (*func)(void)) {
    if (!func) return false;

    struct PEHdlr* new_handler = (struct PEHdlr*)alloc(sizeof(struct PEHdlr));
    if (!new_handler) return false;

    new_handler->func = func;
    new_handler->next = exit_handlers;
    exit_handlers = new_handler;

    return true;
}

__IFN __attribute__((noreturn)) void exit(int status) {
    // Cleanup
    // Exit Functions
    struct PEHdlr* curef = exit_handlers;
    while (curef) {
        curef->func();
        struct PEHdlr* temp = curef;
        curef = curef->next;
        dealloc(temp); // Free the handler
    }

    if (exalloc_ptrs) {
        for (usize_t i = 0; i < exalloc_count; i++) {
            dealloc(exalloc_ptrs[i]);
        }
        dealloc(exalloc_ptrs);
    }

    #if defined(__linux__)
        // Calls exit_group
        #if __PARCH__ == x86_64
            __plib_syscall(231, (llong_t)status, 0, 0, 0, 0, 0);
        #elif __PARCH__ == x86
            __plib_syscall(252, (llong_t)status, 0, 0, 0, 0, 0);
        #elif __PARCH__ == arm32
            __plib_syscall(248, (llong_t)status, 0, 0, 0, 0, 0);
        #elif __PARCH__ == arm64
            __plib_syscall(94, (llong_t)status, 0, 0, 0, 0, 0);
        #endif
    #elif defined(_WIN32)
        ExitProcess((unsigned int)status);
    #endif

    __builtin_unreachable();
}

__IFN __attribute__((noreturn)) void abort(void) {
    #if defined(__linux__)
        // Calls exit_group with status 134 (128 + SIGABRT)
        #if __PARCH__ == x86_64
            __plib_syscall(231, 134, 0, 0, 0, 0, 0);
        #elif __PARCH__ == x86
            __plib_syscall(252, 134, 0, 0, 0, 0, 0);
        #elif __PARCH__ == arm32
            __plib_syscall(248, 134, 0, 0, 0, 0, 0);
        #elif __PARCH__ == arm64
            __plib_syscall(94, 134, 0, 0, 0, 0, 0);
        #endif
    #elif defined(_WIN32)
        TerminateProcess(GetCurrentProcess(), 6);
    #endif

    __builtin_unreachable();
}
