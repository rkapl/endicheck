#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../endicheck.h"

/* The point of the test is to check that the result of calloc is ANY.
 * This is somewhat challanging, because internally malloc uses memset, which
 * uses all kinds of vector extensions */

int main() {
    void* m = calloc(1, 64);
    EC_DUMP_MEM(m, 64);
    EC_CHECK_ENDIANITY(m, 64, "calloc");
}
