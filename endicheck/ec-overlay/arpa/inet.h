#ifndef _EC_ARPA_INET
#define _EC_ARPA_INET

/* Intented to be used with glibc */

#include_next <arpa/inet.h>
#include <valgrind/endicheck.h>

static inline uint16_t ec_htons(uint16_t v)
{
    v = htons(v);
    EC_MARK_ENDIANITY(&v, sizeof(v), EC_TARGET);
    return v;
}
#undef htons
#define htons ec_htons

static inline uint32_t ec_htonl(uint32_t v)
{
    v = htonl(v);
    EC_MARK_ENDIANITY(&v, sizeof(v), EC_TARGET);
    return v;
}
#undef htonl
#define htonl ec_htonl


#endif
