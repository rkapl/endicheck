#ifndef EC_UTIL_H
#define EC_UTIL_H
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#ifndef __BYTE_ORDER__
#error Expected __BYTE_ORDER__ macro
#endif

/* The memory must be swapped for the same test results on big endian */
static inline void swapmem(void* ptr, size_t size) 
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    assert(size%2 == 0);
    uint8_t* cptr = ptr;
    size_t i;
    for(i = 0; i<size/2; i++) {
        uint8_t tmp = cptr[size - i - 1];
        cptr[size - i - 1] = cptr[i];
        cptr[i] = tmp;
    }
#endif
}

#endif
