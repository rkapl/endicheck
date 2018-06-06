#ifndef _EC_NETDB
#define _EC_NETDB

#include_next <netdb.h>
#include <ec_overlay_common.h>

#ifdef EC_MARK_NETDB
static inline int ec_getaddrinfo(const char *node, const char *service,
               const struct addrinfo *hints,
               struct addrinfo **res)
{
    int r = getaddrinfo(node, service, hints, res);
    if (r == 0)
        EC_MARK_ENDIANITY((*res)->ai_addr, sizeof(*(*res)->ai_addr), EC_TARGET);
    return r;
}
#define getaddrinfo ec_getaddrinfo
#endif


#endif
