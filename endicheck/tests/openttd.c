#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

#define T char
#define U int

/* A small sift magic example take from OpenTTD -- it used not to work */

static inline T SB(T *x, const uint8_t s, const uint8_t n, const U d)
{
	*x &= (T)(~((((T)1U << n) - 1) << s));
	*x |= (T)(d << s);
	return *x;
}

int main() {
    T x = 0xFF;
    SB(&x, 0, 4, 0xF);
    EC_DUMP_MEM(&x, sizeof(x));
    return 0;
}
