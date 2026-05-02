// PStdlib C Source file

#define __IPSTDLIB_BUILD
#include <pstdlib.h>

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
    llong_t *args = (llong_t *)(&id + 1);

    #if __PARCH__ == x86_64
        #if defined(__linux__) || defined(__unix__)
            llong_t a[6] = {0};
            for (int i = 0; i < 6; i++)
                a[i] = args[i];
            asm volatile (
                "mov %[num], %%rax\n\t"
                "mov %[a1], %%rdi\n\t"
                "mov %[a2], %%rsi\n\t"
                "mov %[a3], %%rdx\n\t"
                "mov %[a4], %%r10\n\t"
                "mov %[a5], %%r8\n\t"
                "mov %[a6], %%r9\n\t"
                "syscall\n\t"
                "mov %%rax, %[ret]"
                : [ret] "=r"(ret)
                : [num] "r"((llong_t)id), [a1] "r"(a[0]), [a2] "r"(a[1]),
                [a3] "r"(a[2]), [a4] "r"(a[3]), [a5] "r"(a[4]), [a6] "r"(a[5])
                : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9",
                "memory"
            );
        #endif
    #elif __PARCH__ == x86
        #if defined(__linux__) || defined(__unix__)
            int a[5] = {0};
            for (int i = 0; i < 5; i++)
                a[i] = (int)args[i];
            asm volatile (
                "mov %[num], %%eax\n\t"
                "mov %[a1], %%ebx\n\t"
                "mov %[a2], %%ecx\n\t"
                "mov %[a3], %%edx\n\t"
                "mov %[a4], %%esi\n\t"
                "mov %[a5], %%edi\n\t"
                "int $0x80\n\t"
                "mov %%eax, %[ret]"
                : [ret] "=r"(ret)
                : [num] "r"(id), [a1] "r"(a[0]), [a2] "r"(a[1]), [a3] "r"(a[2]),
                [a4] "r"(a[3]), [a5] "r"(a[4])
                : "eax", "ebx", "ecx", "edx", "esi", "edi", "memory"
            );
        #endif
    #elif __PARCH__ == arm64
        llong_t a[8] = {0};
        for (int i = 0; i < 8; i++)
            a[i] = args[i];
        asm volatile (
            "mov x8, %[num]\n\t"
            "mov x0, %[a1]\n\t"
            "mov x1, %[a2]\n\t"
            "mov x2, %[a3]\n\t"
            "mov x3, %[a4]\n\t"
            "mov x4, %[a5]\n\t"
            "mov x5, %[a6]\n\t"
            "mov x6, %[a7]\n\t"
            "mov x7, %[a8]\n\t"
            "svc 0\n\t"
            "mov %[ret], x0"
            : [ret] "=r"(ret)
            : [num] "r"((llong_t)id), [a1] "r"(a[0]), [a2] "r"(a[1]),
            [a3] "r"(a[2]), [a4] "r"(a[3]), [a5] "r"(a[4]), [a6] "r"(a[5]),
            [a7] "r"(a[6]), [a8] "r"(a[7])
            : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
            "memory"
        );

    #elif __PARCH__ == arm32
        llong_t a[7] = {0};
        for (int i = 0; i < 7; i++)
            a[i] = args[i];
        asm volatile (
            "mov r7, %[num]\n\t"
            "mov r0, %[a1]\n\t"
            "mov r1, %[a2]\n\t"
            "mov r2, %[a3]\n\t"
            "mov r3, %[a4]\n\t"
            "mov r4, %[a5]\n\t"
            "mov r5, %[a6]\n\t"
            "mov r6, %[a7]\n\t"
            "svc 0\n\t"
            "mov %[ret], r0"
            : [ret] "=r"(ret)
            : [num] "r"((llong_t)id), [a1] "r"(a[0]), [a2] "r"(a[1]), [a3] "r"(a[2]),
            [a4] "r"(a[3]), [a5] "r"(a[4]), [a6] "r"(a[5]), [a7] "r"(a[6])
            : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "memory"
        );

    #else
        ret = -1; // unknown arch
    #endif

    return ret;
}

__IFN void __plib_reset_env(char** envp, usize_t envp_count) {
    env_vars = alloc(envp_count);
    if (env_vars) {
        copybuf(envp, env_vars, sizeof(char*) * envp_count);
    }
}

__IFN bool copybuf(void* source, void* dest, usize_t size) {
    if (size == 0)
        return true;
    else if (source == PNULL || dest == PNULL)
        return false;

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
    if (size == 0)
        return true;
    else if (buf == PNULL)
        return false;

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

__IFN bool movebuf(void* source, void* dest, usize_t size) {
    if (!copybuf(source, dest, size))
        return false;
    return fillbuf(source, 0, size);
}

__IFN bool cmpbuf(void* a, void* b, usize_t size) {
    byte_t* x = a;
    byte_t* y = b;

    for (usize_t i = 0; i < size; i++)
        if (x[i] != y[i])
            return false;

    return true;
}

__IFN uoff_t findbyte(void* search_area, byte_t byte, usize_t size) {
    // Not Yet implemented
}

__IFN void* exalloc(usize_t size, uint_t type, void* link, bool auto_free) {
    void* ptr = PNULL;
    uint_t prot = 0;

    #if defined(__linux__)
        if (type & __MEMTYPE_EXEC__)
            prot |= PROT_EXEC;
        if (type & __MEMTYPE_NONE__)
            prot |= PROT_NONE;
        if (type & __MEMTYPE_READ__)
            prot |= PROT_READ;
        if (type & __MEMTYPE_WRITE__)
            prot |= PROT_WRITE;
        ptr = mmap(PNULL, size + sizeof(struct PHM_Hdr), prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ptr == MAP_FAILED) {
            ptr = PNULL;
        }
    #elif defined(_WIN32)
        if (type & __MEMTYPE_EXEC__ && type & __MEMTYPE_READ__ &&
            type & __MEMTYPE_WRITE__)
            prot = PAGE_EXECUTE_READWRITE;
        else if (type & __MEMTYPE_EXEC__ && type & __MEMTYPE_READ__)
            prot = PAGE_EXECUTE_READ 
        else if (type & __MEMTYPE_EXEC__) 
            prot = PAGE_EXECUTE;
        else if (type & __MEMTYPE_NONE__)
            prot = PAGE_NOACCESS;
        else if (type & __MEMTYPE_WRITE__)
            prot = PAGE_READWRITE;
        else if (type & __MEMTYPE_READ__)
            prot = PAGE_READONLY;
        else
            prot = PAGE_NOACCESS;

        ptr = VirtualAlloc(PNULL, size + sizeof(struct PHM_Hdr), MEM_COMMIT | MEM_RESERVE, prot);
    #else
        ptr = PNULL;
    #endif
    
    if (ptr == PNULL) return PNULL;

    struct PHM_Hdr* hdr = (struct PHM_Hdr*)ptr;
    hdr->size = size;
    hdr->flags = auto_free ? __PHM_HDR_FLAG_AUTO_FREE__ | __PHM_HDR_FLAG_ALLOCATED__ : __PHM_HDR_FLAG_ALLOCATED__;
    hdr->next = link ? (struct PHM_Hdr*)((ubyte_t*)link - sizeof(struct PHM_Hdr)) : PNULL;
    hdr->auto_free_idx = 0;
    hdr->next_count = 0;
    if (link)
        hdr->next_count = 1;

    void* rptr = (void*)((ubyte_t*)ptr + sizeof(struct PHM_Hdr));
    if (auto_free) {
        usize_t idx = 0;
        if (exalloc_free_count > 0) {
            idx = exalloc_free_stack[--exalloc_free_count];
        } else {
            if (exalloc_count >= exalloc_capacity) {
                usize_t newcap = exalloc_capacity ? exalloc_capacity * 2 : 16;
                
                void* nptr = exalloc(newcap * sizeof(void*), __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL, false);
                if (!nptr) return rptr; // Cant auto free this
                copybuf(exalloc_ptrs, nptr, sizeof(void*) * exalloc_capacity);
                dealloc(exalloc_ptrs);
                exalloc_ptrs = nptr;

                nptr = exalloc(newcap * sizeof(usize_t), __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL, false);
                if (!nptr) return rptr;
                copybuf(exalloc_free_stack, nptr, sizeof(usize_t) * exalloc_capacity);
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
    return exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL, true);
}

__IFN bool dealloc(void* ptr) {
    if (ptr == PNULL)
        return false;
    struct PHM_Hdr* hdr = ptr - sizeof(struct PHM_Hdr);

    if (hdr->next && hdr->next_count > 0)
        dealloc(hdr->next);

    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__))
        return false; // DeAllocated Probably

    if (hdr->flags & __PHM_HDR_FLAG_AUTO_FREE__) {
        // Add a free slot
        if (exalloc_ptrs[hdr->auto_free_idx] == ptr) {
            exalloc_ptrs[hdr->auto_free_idx] = PNULL;
            if (exalloc_free_count < exalloc_capacity)
                exalloc_free_stack[exalloc_free_count++] = hdr->auto_free_idx;
        }
    }

    usize_t size = hdr->size + sizeof(struct PHM_Hdr);
    #if defined(__linux__)
        munmap((void* )hdr, size); // Hdr already points to the starting pos
    #elif defined(_WIN32)
        VirtualFree((void* )hdr, size, MEM_RELEASE);
    #else
        return false;
    #endif

    return true;
}

__IFN void* zalloc(usize_t size) {
    void* ptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL, true);
    if (ptr == PNULL)
        return ptr;
    if (!fillbuf(ptr, 0, size)) {
        dealloc(ptr);
        return PNULL;
    }
    return ptr;
}

__IFN void* ralloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, __MEMTYPE_WRITE__ | __MEMTYPE_READ__, NULL, true);
    if (nptr == PNULL) {
        return PNULL;
    }
    struct PHM_Hdr* hdr = ptr - sizeof(struct PHM_Hdr);
    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__)) return PNULL; // Cant reallocate
    copybuf(ptr, nptr, hdr->size);

    dealloc(ptr);
    return nptr;
}

__IFN void* rzalloc(void* ptr, usize_t size) {
    void* nptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, ptr, true);
    if (nptr == PNULL) {
        return PNULL;
    }
    if (!fillbuf(nptr, 0, size)) {
        dealloc(nptr);
        return PNULL;
    }

    struct PHM_Hdr* hdr = ptr - sizeof(struct PHM_Hdr);
    if (!(hdr->flags & __PHM_HDR_FLAG_ALLOCATED__)) return PNULL; // Cant reallocate
    copybuf(ptr, nptr, hdr->size);

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

__IFN usize_t strlen(const char* str) {
    const char* s = str;
    while (*s) s++;
    return s - str;
}

__IFN bool strcopy(const char* src, char* dest) {
    return copybuf((void*)src, (void*)dest, strlen(src) + 1);
}

__IFN bool strscopy(const char* src, char* dest, usize_t size) {
    return copybuf((void*)src, (void*)dest, size);
}

__IFN bool strcmp(char* a, char* b) {
    usize_t n1 = strlen(a);
    usize_t n2 = strlen(b);
    usize_t n = n1 > n2 ? n2 : n1;

    return cmpbuf(a, b, n);
}

__IFN bool strncmp(char* a, char* b, usize_t size) {
    usize_t n1 = strlen(a);
    usize_t n2 = strlen(b);
    usize_t fallback_n = n1 > n2 ? n2 : n1;

    usize_t n = size > fallback_n ? fallback_n : size;

    return cmpbuf(a, b, n);
}

__IFN char* strfindc(char* str, char c, usize_t occurance) {
    usize_t n = strlen(str);
    usize_t coccur = 0;

    char* cstr = str;

    for (usize_t i = 0; i < n; i++) {
        cstr = (char*)(str + i);
        if (str[i] == c) {
            coccur++;
            if (occurance == 0 || coccur == occurance) {
                return cstr;
            }
        }
    }
    return PNULL;
}

__IFN char* strsplit(char* str, char c, usize_t occurance, bool first_part) {
    usize_t n = strlen(str);
    usize_t coccur = 0;

    char* cstr = str;

    for (usize_t i = 0; i < n; i++) {
        cstr = (char*)(str + i);
        if (str[i] == c) {
            coccur++;
            if (occurance == 0 || coccur == occurance) {
                usize_t s = first_part ? i + 2 : n - (i + 2);
                if (s == 0) return PNULL;
                char* split = alloc(s);
                if (!split) return PNULL;
                if (first_part)
                    strscopy(cstr, split, s);
                else
                    strscopy(str, split, s);
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

        if (!strncmp(e, name, len) && e[len] == '=') {
            return e + len + 1;
        }
    }
    return PNULL;
}

__IFN bool setenv(const char* name, const char* val, bool overwrite) {
    if (!env_vars || !name || !val) return false;

    usize_t nlen = strlen(name);
    usize_t vlen = strlen(val);

    // Search existing
    for (usize_t i = 0; i < env_count; i++) {
        char* e = env_vars[i];
        if (!e) continue;

        if (!strncmp(e, name, nlen) && e[nlen] == '=') {
            if (!overwrite)
                return true;

            // Replace existing
            usize_t len = nlen + 1 + vlen + 1;
            char* ne = alloc(len);
            if (!ne) return false;

            // build "name=value"
            copybuf((void*)name, ne, nlen);
            ne[nlen] = '=';
            copybuf((void*)val, ne + nlen + 1, vlen);
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

    copybuf((void*)name, ne, nlen);
    ne[nlen] = '=';
    copybuf((void*)val, ne + nlen + 1, vlen);
    ne[len - 1] = '\0';

    env_vars[env_count++] = ne;

    return true;
}

__IFN bool aexitf(void (*func)(void)) {
    if (func == NULL) return false;

    struct PEHdlr* new_handler = (struct PEHdlr*)alloc(sizeof(struct PEHdlr));
    if (new_handler == NULL) return false;

    new_handler->func = func;
    new_handler->next = exit_handlers;
    exit_handlers = new_handler;

    return true;
}

__IFN __attribute__((noreturn)) void exit(int status) {
    // Cleanup
    // Exit Functions
    struct PEHdlr* curef = exit_handlers;
    while (curef != NULL) {
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
            __plib_syscall(231, (llong_t)status);
        #elif __PARCH__ == x86
            __plib_syscall(252, (llong_t)status);
        #elif __PARCH__ == arm32
            __plib_syscall(248, (llong_t)status);
        #elif __PARCH__ == arm64
            __plib_syscall(94, (llong_t)status);
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
            __plib_syscall(231, 134);
        #elif __PARCH__ == x86
            __plib_syscall(252, 134);
        #elif __PARCH__ == arm32
            __plib_syscall(248, 134);
        #elif __PARCH__ == arm64
            __plib_syscall(94, 134);
        #endif
    #elif defined(_WIN32)
        TerminateProcess(GetCurrentProcess(), 6);
    #endif

    __builtin_unreachable();
}
