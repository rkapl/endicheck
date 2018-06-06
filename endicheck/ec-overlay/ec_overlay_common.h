#ifndef _EC_OVERLAY_COMMON
#define _EC_OVERLAY_COMMON

#include <valgrind/endicheck.h>

#ifdef EC_CHECK_MARK_ALL
#define EC_MARK_ALL
#define EC_CHECK_ALL
#endif

#ifdef EC_MARK_ALL
#define EC_MARK_READ
#define EC_MARK_RECV
#define EC_MARK_NETDB
#endif

#ifdef EC_CHECK_ALL
#define EC_CHECK_WRITE
#define EC_CHECK_SEND
#endif

#endif
