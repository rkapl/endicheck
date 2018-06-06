#ifndef _EC_SYS_SOCKET
#define _EC_SYS_SOCKET

#include_next <sys/socket.h>
#include <valgrind/endicheck.h>

#ifdef EC_CHECK_SEND
static inline ssize_t ec_send(int sockfd, const void *buf, size_t len, int flags)
{
    EC_CHECK_ENDIANITY(buf, len, "send");
    return send(sockfd, buf, len, flags);
}
#define send ec_send

static inline ssize_t ec_sendto(int sockfd, const void *buf, size_t len, int flags,
              const struct sockaddr *dest_addr, socklen_t addrlen)
{
    EC_CHECK_ENDIANITY(buf, len, "send");
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
#define sendto ec_sendto

static inline ssize_t ec_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    struct iovec *iov = msg->msg_iov;
    int i = 0;
    for(i = 0; i<msg->msg_iovlen; i++, iov++) {
        EC_CHECK_ENDIANITY(iov->iov_base, iov->iov_len, "sendmsg");
    }
    return sendmsg(sockfd, msg, flags);
}
#define sendmsg ec_sendmsg

#endif

#ifdef EC_MARK_RECV
static inline ssize_t ec_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t r = recv(sockfd, buf, len, flags);
    if (r > 0)
        EC_MARK_ENDIANITY(buf, r, EC_TARGET);
    return r;
}
#define recv ec_recv

static inline ssize_t ec_recvfrom(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t r = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (r > 0)
        EC_MARK_ENDIANITY(buf, r, EC_TARGET);
    return r;
}
#define recvfrom ec_recvfrom

static inline ssize_t ec_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t r = recvmsg(sockfd, msg, flags);
    if (r > 0) {
        struct iovec *iov = msg->msg_iov;
        int i = 0;
        size_t remaining = r;
        size_t chunk = 0;
        for(i = 0; i<msg->msg_iovlen; remaining -= chunk, i++, iov++) {
            chunk = iov->iov_len;
            if (chunk > remaining)
                chunk = remaining;
            EC_MARK_ENDIANITY(iov->iov_base, chunk, EC_TARGET);
        }
    }
    return r;
}
#define recvmsg ec_recvmsg
#endif

#endif
