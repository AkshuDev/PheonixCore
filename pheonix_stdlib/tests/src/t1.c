#include <pstdlib.h>
#include <pio.h>

int main() {
    // Basic Printing
    print("Printing is working!\n", 21);

    // Allocate some zeroed memory
    char* buf = (char*)zalloc(43);
    copybuf("File Opening/Writing/Closing is working!\n", buf, 42);
    buf[42] = '\0';

    PIO_Stream* f = sopen_file("t1.txt", PSTREAM_FLAG_WRITE);
    swrite(f, buf, 43);
    sclose(f);

    print("Created File [t1.txt] and written contents into it!\n", 52);
    PIO_Stream* f2 = sopen_file("t1.txt", PSTREAM_FLAG_READ); // Reopening just to ensure reading and opening works, however can also use write and read both at once
    // Dealloc buffer
    dealloc(buf);

    char* buf2 = (char*)alloc(52);
    sread(f2, buf2, 43);
    sclose(f2);
    print(buf2, 43);
    print("\n", 1);
    dealloc(buf2);

    return 0;
}
