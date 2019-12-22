#include <netdb.h>
#include <netinet/in.h>
#include <memory>

struct sockaddr_in getsockaddrbyhost(const char *host)
{
    hostent *h = gethostbyname(host);
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = *(in_addr *)(h->h_addr);
    return addr;
}