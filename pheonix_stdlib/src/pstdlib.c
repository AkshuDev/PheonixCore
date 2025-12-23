// PStdlib C Source file

#define __IPSTDLIB_BUILD
#include <pstdlib.h>

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

__IFN bool copybuf(void *source, void *dest, usize_t size) {
    if (size == 0)
        return true;
    else if (size < 0 || source == PNULL || dest == PNULL)
        return false;

    byte_t *dst = (byte_t *)dest;
    byte_t *src = (byte_t *)source;

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

    usize_t remain = size - 1;
    if (remain >= sizeof(u64)) {
        u64 *wd = (u64 *)(dst + i);
        u64 *ws = (u64 *)(src + i);
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

__IFN bool fillbuf(void *buf, byte_t value, usize_t size) {
    if (size == 0)
        return true;
    else if (size < 0 || buf == PNULL)
        return false;

    byte_t *dest = (byte_t *)buf;

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

    usize_t remain = size - 1;
    if (remain >= sizeof(u64)) {
        u64 pat = (u64)value * (u64)0x0101010101010101ULL;
        u64 *wd = (u64 *)(dest + i);
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

__IFN bool movebuf(void *source, void *dest, usize_t size) {
    if (!copybuf(source, dest, size))
        return false;
    return fillbuf(source, 0, size);
}

__IFN bool cmpbuf(void *a, void *b, usize_t size) {
    // Not yet implemented
}

__IFN uoff_t findbyte(void *search_area, byte_t byte, usize_t size) {
    // Not Yet implemented
}

__IFN void *exalloc(usize_t size, uint_t type, void *link) {
    void *ptr = PNULL;
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

    struct PHM_Hdr *hdr = (struct PHM_Hdr *)ptr;
    hdr->size = size;
    hdr->flags = 0; // Normal Allocated
    hdr->next = link ? link - sizeof(struct PHM_Hdr) : PNULL;
    if (link)
        hdr->next_count++;

    return (void*)((ubyte_t*)ptr + sizeof(struct PHM_Hdr));
}

__IFN void *alloc(usize_t size) {
    return exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL);
}

__IFN bool dealloc(void *ptr) {
    if (ptr == PNULL)
        return false;
    struct PHM_Hdr *hdr = ptr - sizeof(struct PHM_Hdr);

    if (hdr->next && hdr->next_count > 0)
        dealloc(hdr->next);

    if (hdr->flags != 0)
        return false; // DeAllocated Probably
    usize_t size = hdr->size + sizeof(struct PHM_Hdr);
#if defined(__linux__)
    munmap((void *)hdr, size); // Hdr already points to the starting pos
#elif defined(_WIN32)
    VirtualFree((void *)hdr, size, MEM_RELEASE);
#else
    return false;
#endif

    return true;
}

__IFN void *zalloc(usize_t size) {
    void *ptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, PNULL);
    if (ptr == PNULL)
        return ptr;
    if (!fillbuf(ptr, 0, size)) {
        dealloc(ptr);
        return PNULL;
    }
    return ptr;
}

__IFN void *ralloc(void *ptr, usize_t size) {
    void *nptr = exalloc(size, __MEMTYPE_WRITE__ | __MEMTYPE_READ__, ptr);
    if (nptr == PNULL) {
        dealloc(ptr);
        return PNULL;
    }
    return ptr;
}

__IFN void *rzalloc(void *ptr, usize_t size) {
    void *nptr = exalloc(size, __MEMTYPE_READ__ | __MEMTYPE_WRITE__, ptr);
    if (nptr == PNULL) {
        dealloc(ptr);
        return PNULL;
    }
    if (!fillbuf(nptr, 0, size)) {
        dealloc(ptr);
        return PNULL;
    }
    return ptr;
}
