#include <pstdlib.h>
#include <pio.h>

#define ITERATIONS 200
#define BLOCKS 50

#define TEST(name, condition) do { \
    if (condition) { \
        fprint("[PASS] %s\n", name); \
        passed++; \
    } else { \
        fprint("[FAIL] %s\n", name); \
        failed++; \
    } \
} while (0)

static void exit_hook_1(void) {
    fprint("[exit] hook 1\n");
}

static void exit_hook_2(void) {
    fprint("[exit] hook 2\n");
}

static void test_exit(void) {
    fprint("\n=== EXIT TEST ===\n");

    // Register exit handlers (tests LIFO + cleanup correctness)
    aexitf(exit_hook_1);
    aexitf(exit_hook_2);
}

static void test_fprintf(void) {
    fprint("\n=== FPRINTF TEST ===\n");

    fprints(
        s_stdout,
        "String test: %s\n"
        "String test (width test): %2s (Ans: Wo)\n"
        "NULL String test: %s\n"
        "Character test: %c (Ans: h)\n"
        "Int Test (with percentage test): (%%d) %d (%%i) %i (Ans: 42)\n"
        "Int Test (with width): %1i (Ans: 4)\n"
        "Int Test (with prefix test): %+d (Ans: +42)\n"
        "Int Test (with prefix test + l test): *%*!+ld (Ans: +-42)\n"
        "Int Test (with prefix test + l test): % ld (Ans:  42)\n"
        "Int Test (with prefix test): *%*! d (Ans:  -42)\n"
        "UInt Test (with prefix test): %+u (Ans: +72)\n"
        "UInt Test (l test): %lu (Ans: 1099511627775)\n"
        "Hex Test (with prefix test): %#x (Ans: 0xff)\n"
        "Hex Test (l test + caps): %lX (Ans: FFFFFFFFFF)\n"
        "Pointer Test (with caps): *%*P (Ans: 0xFFFFFFFFFF)\n"
        "Bin Test (with prefix test): *%*#b (Ans: 0b100)\n"
        "Octal Test (with prefix test): %#o (Ans: 0o144)\n"
        "Float Test: %.3f (Ans: 0.537)\n"
        "Double Test: *%*l.9f (Ans: 0.123456789)\n",
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
}

static void test_string_io(void) {
    fprint("\n=== PIO STRING STREAM TEST ===\n");

    int passed = 0;
    int failed = 0;

    // Open a writable string stream
    char buffer[32] = {0};
    PIO_Stream* s = sopen_string(buffer, sizeof(buffer), PSTREAM_FLAG_READ | PSTREAM_FLAG_WRITE);

    TEST("Open writable string stream", s != PNULL);
    if (!s) goto finish;

    // Basic write
    const char hello[] = "Hello";
    usize_t written = swrite(s, hello, sizeof(hello) - 1);

    TEST("Basic write", written == sizeof(hello) - 1);
    TEST("Buffer contents after write", cmpbuf(buffer, hello, sizeof(hello) - 1) == 0);
    TEST("Cursor after write", stell(s) == 5);

    // Seek to beginning
    TEST("SEEK_SET to beginning", sseek(s, 0, SEEK_SET));
    TEST("Cursor after SEEK_SET", stell(s) == 0);

    // Basic read
    char output[sizeof(buffer)] = {0};
    usize_t received = sread(s, output, 5);

    TEST("Basic read", received == 5);
    TEST("Read data correctness", cmpbuf(output, hello, 5) == 0);
    TEST("Cursor after read", stell(s) == 5);

    // Read the remaining bytes
    received = sread(s, output, sizeof(output));
    TEST("Read remaining bytes", received == sizeof(buffer) - 5);
    TEST("EOF at exact end", seof(s));

    // Seek to end
    TEST("SEEK_END to end", sseek(s, 0, SEEK_END));
    TEST("Cursor at end", stell(s) == sizeof(buffer));

    // Relative seek
    TEST("SEEK_CUR backwards", sseek(s, -2, SEEK_CUR));
    TEST("Relative seek position", stell(s) == sizeof(buffer) - 2);

    // Bounded write
    const char overflow[] = "ABCDEFGH";
    written = swrite(s, overflow, sizeof(overflow) - 1);

    TEST("Bounded write", written == 2);
    TEST("Cursor after bounded write", stell(s) == sizeof(buffer));
    TEST("Bounded write contents", cmpbuf(buffer + 30, "AB", 2) == 0);

    // Read beyond buffer
    received = sread(s, output, 1);
    TEST("Read beyond buffer", received == 0);

    // Invalid seek positions
    TEST("SEEK_SET to exact end", sseek(s, sizeof(buffer), SEEK_SET));
    TEST("Reject seek beyond end", !sseek(s, sizeof(buffer) + 1, SEEK_SET));
    TEST("Reject negative SEEK_SET", !sseek(s, -1, SEEK_SET));
    TEST("Reject SEEK_CUR beyond end", !sseek(s, 1, SEEK_CUR));
    TEST("Reject SEEK_END beyond end", !sseek(s, 1, SEEK_END));

    // Binary data test
    unsigned char binary[8] = {0x00, 0xFF, 0x01, 0x80, 0x00, 0x42, 0xAA, 0x55};
    unsigned char binary_out[8] = {0};
    PIO_Stream* bs = sopen_string((char*)binary, sizeof(binary), PSTREAM_FLAG_READ);

    TEST("Open binary string stream", bs != PNULL);
    if (bs) {
        received = sread(bs, binary_out, sizeof(binary_out));

        TEST("Binary read", received == sizeof(binary));
        TEST("Binary data integrity", cmpbuf(binary, binary_out, sizeof(binary)) == 0);
        TEST("Binary EOF behavior", seof(bs));

        sclose(bs);
    }

    // Read-only string stream
    PIO_Stream* rs = sopen_string("Read only", 9, PSTREAM_FLAG_READ);

    TEST("Open read-only string stream", rs != PNULL);
    if (rs) {
        received = sread(rs, output, 8);
        TEST("Read-only stream read", received == 8);
        TEST("Read-only stream contents", cmpbuf(output, "Read only", 8) == 0);
        sclose(rs);
    }

    // Close and ownership test
    TEST("Close string stream", sclose(s));
    TEST("Original buffer survives close", buffer[0] == 'H' && buffer[30] == 'A' && buffer[31] == 'B');

    // Empty stream test
    TEST("Zero-length stream rejected", !sopen_string("", 0, PSTREAM_FLAG_NONE));

	finish: {
    	fprint("\nPIO RESULTS: %d passed, %d failed\n", passed, failed);
	}
}

static void test_env(void) {
    fprint("\n=== ENV TEST ===\n");

    // Environment test
    char* env = retenv("PATH");
    if (env) {
        fprint("Environment (PATH): %s\n", env);
    } else {
        fprint("No environment PATH\n");
    }

    // String copy test
    char bigbuf[256];
    fillbuf(bigbuf, 'A', sizeof(bigbuf) - 1);
    bigbuf[sizeof(bigbuf) - 1] = '\0';

    char copy[sizeof(bigbuf)];
    strcopy(copy, bigbuf);
    strscopy(bigbuf, copy, 128);
}

static void test_alloc(void) {
    fprint("\n=== ALLOC TEST ===\n");

    // Heap stress (alloc/free chaos)
    void* ptrs[BLOCKS];

    for (int i = 0; i < BLOCKS; i++) {
        usize_t size = 1 + (i * 7) % 128;
        ptrs[i] = alloc(size);

        if (!ptrs[i]) {
            fprint("[FAIL] Allocation block %d\n", i);
            continue;
        }

        fillbuf(ptrs[i], (byte_t)i, size);
    }

    // Deallocate in reverse order
    for (int i = BLOCKS - 1; i >= 0; i--) {
        if (ptrs[i]) dealloc(ptrs[i]);
    }

    // Reallocation stress
    void* r = alloc(16);
    if (!r) {
        fprint("[FAIL] Initial realloc allocation\n");
        return;
    }

    for (int i = 0; i < ITERATIONS; i++) {
        usize_t size = (i % 64) + 1;
        void* next = ralloc(r, size);

        if (!next) {
            fprint("[FAIL] Reallocation failed\n");
            dealloc(r);
            return;
        }

        r = next;
        fillbuf(r, (byte_t)i, size);
    }

    dealloc(r);
}

static void test_buffer(void) {
    fprint("\n=== BUFFER TEST ===\n");

    // Buffer edge cases
    char a[16];
    char b[16];

    fillbuf(a, 0xAA, sizeof(a));
    movebuf(b, a, sizeof(a));

    if (cmpbuf(a, b, sizeof(a)) == 0) {
        fprint("movebuf/cmpbuf OK\n");
    }

    // Alignment stress
    void* p = alloc(64);
    if (!p) {
        fprint("[FAIL] Alignment allocation\n");
        return;
    }

    void* ap = alignptr(p, 16);
    if (isaligned(ap, 16)) {
        fprint("alignment OK\n");
    }

    dealloc(p);
}

static void test_syscall(void) {
    fprint("\n=== SYSCALL TEST ===\n");

    // Recursive syscall pressure
    for (int i = 0; i < 1000; i++) {
        #if defined(__linux__)
            __plib_syscall(39, 0, 0, 0, 0, 0, 0); // getpid
        #endif
    }
}

static void test_edge_cases(void) {
    fprint("\n=== EDGE CASE TEST ===\n");

    // Intentional allocation edge cases
    char* bad = alloc(1);
    if (bad) {
        fillbuf(bad, 0xFF, 1);
        dealloc(bad);
    }

    bad = alloc(0);
    dealloc(bad);
}

static void test_time(void) {
	fprint("\n=== TIME TEST ===\n");

	fprint("Unix Timestamp: %llu\n", time_unix());
	fprint("Uptime (ns): %llu\n", time_ns());
	fprint("Uptime (us): %llu\n", time_us());
	fprint("Uptime (ms): %llu\n", time_ms());
	fprint("Uptime (s): %llu\n", time_s());
}

int main(int argc, char** argv) {
    fprint("=== PStdLib STRESS TEST START ===\n");

    bool exit_test = false;
    bool fprintf_test = false;
    bool io_string_test = false;
    bool env_test = false;
    bool alloc_test = false;
    bool buffer_test = false;
    bool syscall_test = false;
    bool edge_test = false;
	bool time_test = false;
    bool all_tests = argc <= 1;

    // Parse test arguments
    for (int i = 1; i < argc; i++) {
        char* opt = argv[i];

        if (strcmp(opt, "exit") == 0) exit_test = true;
        else if (strcmp(opt, "fprintf") == 0) fprintf_test = true;
        else if (strcmp(opt, "io-string") == 0) io_string_test = true;
        else if (strcmp(opt, "env") == 0) env_test = true;
        else if (strcmp(opt, "alloc") == 0) alloc_test = true;
        else if (strcmp(opt, "buffer") == 0) buffer_test = true;
        else if (strcmp(opt, "syscall") == 0) syscall_test = true;
        else if (strcmp(opt, "edge") == 0) edge_test = true;
		else if (strcmp(opt, "time") == 0) time_test = true;
        else if (strcmp(opt, "all") == 0) {
            all_tests = true;
            break;
        }
    }

    if (all_tests) {
        exit_test = true;
        fprintf_test = true;
        io_string_test = true;
        env_test = true;
        alloc_test = true;
        buffer_test = true;
        syscall_test = true;
        edge_test = true;
		time_test = true;
    }

    if (exit_test) test_exit();
    if (fprintf_test) test_fprintf();
    if (io_string_test) test_string_io();
    if (env_test) test_env();
    if (alloc_test) test_alloc();
    if (buffer_test) test_buffer();
    if (syscall_test) test_syscall();
    if (edge_test) test_edge_cases();
	if (time_test) test_time();

    fprint("\n=== STRESS TEST COMPLETE ===\n");
    return 0;
}
