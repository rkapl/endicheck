# EndiCheck

EndiCheck is a Valgrind tool to help you detect missing byte-swaps in your
program.

EndiCheck is distributed as a fork of Valgrind (this repository you are
browsing).

Note: Original Valgrind readme is available in the `README.valgrind` file.

# Build & install

To build and install Valgrind, run;

    ./autogen.sh && ./configure --prefix=/opt/endicheck && make && sudo make install

It is recommanded to use --prefix to install into other-than-default location,
since you typically do not want to replace your system's installation of
Valgrind. EndiCheck still contains all the original Valgrind tools, like
MemCheck, but it might not contain all the latest updates or distribution
patches.

It is also possible to try out EndiCheck without the `make install` step. Use the
`./vg-in-place` script to run EndiCheck in that case.

# Run

    /opt/endicheck/bin/valgrind --tool=endicheck ls -l

This should run `ls -l` and produce more errors. However, to take advantage of
EndiCheck (and check for some real errors), you have to annotate your program.

# Annotations

Let's start with a simple example program:

```c
#include <stdint.h>
#include <byteswap.h>
#include <unistd.h>
#include <endian.h>

int main() {
   uint32_t x = 0xDEADBEEF;
   x = htobe32(x);
   write(0, &x, sizeof(x));
   return 0;
}
```

We want to check that this program outputs only data of correct endianity. For
that, we need to insert calls to EndiCheck into the `htobe32` and `write`
functions. A version with such changes is below.

```c
#include <valgrind/endicheck.h>
#include <stdint.h>
#include <byteswap.h>
#include <unistd.h>
/* #include <endian.h> */

static uint32_t htobe32(uint32_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    x = bswap_32(x);
#endif
    EC_MARK_ENDIANITY(&x, sizeof(x), EC_TARGET);
    return x;
}

static int ec_write(int file, const void *buffer, size_t count) {
    EC_CHECK_ENDIANITY(buffer, count, NULL);
    return write(file, buffer, count);
}
#define write ec_write

int main() {
   uint32_t x = 0xDEADBEEF;
   x = htobe32(x);
   write(0, &x, sizeof(x));
   return 0;
}
```

If you remove the `htobe32` call EndiCheck will emit an error. Naturally this is
an overkill for such a small program, but EndiCheck can track data in more
complex programs too.

In some programs that use standard operating functions `write` or `htonl`, you
can use the EndiCheck overlay headers.  Annotating the program can then be as
simmple as adding `-I/opt/endicheck/include/ec-overlay` to your build (well, if
you are lucky).

# Limitations

EndiCheck currently works only for data leaving the program. Opposite direction
is not yet implemented.
