#ifndef _EC_UNISTD
#define _EC_UNISTD

#include_next <unistd.h>
#include <ec_overlay_common.h>

#ifdef EC_CHECK_WRITE
static inline ssize_t ec_write(int fd, const void *buf, size_t count)
{
    EC_CHECK_ENDIANITY(buf, count, "write");
    return write(fd, buf, count);
}
#define write ec_write
#endif

#ifdef EC_MARK_READ
ssize_t ec_read(int fd, void *buf, size_t count)
{
    ssize_t r = read(fd, buf, count);
    if (r > 0)
        EC_MARK_ENDIANITY(buf, r, EC_TARGET);
    return r;
}
#define read ec_read
#endif

#endif
