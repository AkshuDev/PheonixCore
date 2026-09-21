#include <pstdlib.h>
#include <pio.h>

#define ITERATIONS 200
#define FILES 10
#define BLOCKS 50

static void exit_hook_1(void) {
    print("[exit] hook 1\n", 15);
}

static void exit_hook_2(void) {
    print("[exit] hook 2\n", 15);
}

int main(int argc, char** argv) {
    print("=== PStdLib STRESS TEST START ===\n", 34);

    // fprintf test
    fprint("[formating print] stress test...\n");
    fprints(
        s_stdout,
        "String test: %s\n"
        "String test (width test): %2s (Ans: Wo)\n"
    "NULL String test: %s\n"
    "Character test: %c (Ans: h)\n"
    "Int Test (with percentage test): (%%d) %d (%%i) %i (Ans: 42)\n"
    "Int Test (with width): %1i (Ans: 4)\n"
    "Int Test (with prefix test): %+d (Ans: +42)\n"
    "Int Test (with prefix test + l test): %!+ld (Ans: +-42)\n"
    "Int Test (with prefix test + l test): % ld (Ans:  42)\n"
    "Int Test (with prefix test): %! d (Ans:  -42)\n"
    "UInt Test (with prefix test): %+u (Ans: +72)\n"
    "UInt Test (l test): %lu (Ans: 1099511627775)\n"
    "Hex Test (with prefix test): %#x (Ans: 0xff)\n"
    "Hex Test (l test + caps): %lX (Ans: FFFFFFFFFF)\n"
    "Pointer Test (with caps): %P (Ans: 0xFFFFFFFFFF)\n"
    "Bin Test (with prefix test): %#b (Ans: 0b100)\n"
    "Octal Test (with prefix test): %#o (Ans: 0o144)\n"
    "Float Test: %.3f (Ans: 0.537)\n"
    "Double Test: %l.9f (Ans: 0.123456789)\n",
        "Works",
        "Works",
        PNULL,
        'h',
        42, 42,
        42,
        42,
        -42,
        42,
        -42,
        72,
        0xFFFFFFFFFF,
        0xFF,
        0xFFFFFFFFFF,
        0xFFFFFFFFFF,
        4,
        100,
        0.537,
        0.123456789
    );

    // Register exit handlers (tests LIFO + cleanup correctness)
    aexitf(exit_hook_1);
    aexitf(exit_hook_2);

    // Heap Stress (alloc/free chaos)
    print("[heap] stress test...\n", 23);

    void* ptrs[BLOCKS];

    for (int i = 0; i < BLOCKS; i++) {
        ptrs[i] = alloc(1 + (i * 7) % 128);
        fillbuf(ptrs[i], (byte_t)(i), 1 + (i * 7) % 128);
    }

    // shuffle dealloc order
    for (int i = BLOCKS - 1; i >= 0; i--) {
        dealloc(ptrs[i]);
    }

    print("[heap] realloc stress...\n", 27);

    void* r = alloc(16);
    for (int i = 0; i < ITERATIONS; i++) {
        r = ralloc(r, (i % 64) + 1);
        fillbuf(r, (byte_t)i, (i % 64) + 1);
    }
    dealloc(r);

    // String + env stress
    print("[string/env] stress...\n", 25);

    char* env = retenv("PATH");
    if (env) {
        fprint("Environment (PATH): %s\n", env);
    } else {
        fprint("No environment PATH\n");
    }

    char bigbuf[256];
    fillbuf(bigbuf, 'A', 255);
    bigbuf[255] = '\0';

    char copy[256];
    strcopy(copy, bigbuf);
    strscopy(bigbuf, copy, 128);

    // File IO chaos test (Works but is really annoying so i closed it)
    // print("[io] file stress...\n", 22);

    // for (int i = 0; i < FILES; i++) {
    //     char name[32] = "fileX.txt";
    //     name[4] = '0' + i;

    //     PIO_Stream* f = sopen_file(name, PSTREAM_FLAG_WRITE);

    //     for (int j = 0; j < 20; j++) {
    //         char line[64];
    //         fillbuf(line, 'A' + (i + j) % 26, 63);
    //         line[63] = '\n';
    //         swrite(f, line, 64);
    //     }

    //     sclose(f);
    // }

    // // Read them back randomly
    // for (int i = FILES - 1; i >= 0; i--) {
    //     char name[32] = "fileX.txt";
    //     name[4] = '0' + i;

    //     PIO_Stream* f = sopen_file(name, PSTREAM_FLAG_READ);

    //     char* buf = alloc(128);
    //     sread(f, buf, 127);
    //     buf[127] = '\0';

    //     print(buf, strlen(buf));
    //     print("\n", 1);

    //     dealloc(buf);
    //     sclose(f);
    // }

    // Buffer edge cases
    print("[buffer] edge cases...\n", 25);

    char a[16];
    char b[16];

    fillbuf(a, 0xAA, 16);
    movebuf(b, a, 16);

    if (cmpbuf(a, b, 16)) {
        print("movebuf/cmpbuf OK\n", 19);
    }

    // Alignment stress
    print("[align] tests...\n", 18);

    void* p = alloc(64);
    void* ap = alignptr(p, 16);

    if (isaligned(ap, 16)) {
        print("alignment OK\n", 14);
    }

    dealloc(p);

    // Recursive syscall pressure
    print("[syscall] pressure...\n", 23);

    for (int i = 0; i < 1000; i++) {
        #ifdef __linux__
            __plib_syscall(39); // getpid (safe syscall spam)
        #endif
    }

    // Intentional misuse (sanity breaker)
    print("[stress] intentional edge misuse...\n", 38);

    char* bad = alloc(1);
    fillbuf(bad, 0xFF, 1);
    dealloc(bad);

    bad = alloc(0); // edge case test
    dealloc(bad); // should not crash

    // END
    print("=== STRESS TEST COMPLETE ===\n", 30);

    return 0;
}