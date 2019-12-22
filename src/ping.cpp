//
// Created by JiYang on 2019-12-14.
//

#include "log.h"
#include <errno.h>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>
#include "checksum.cpp"

namespace NetUtility
{

#define TAG "NetUtility"
#define BUFFER_SIZE 1500

void doping(int signal);

int s;
struct sockaddr_in serveraddr;
int step, max = 0;
char *hostname, *ipadrr;

void ping(const char *host, int maxstep)
{
    max = maxstep;
    struct timeval tval;
    struct itimerval timer;
    struct sigaction act;

    /* Setting the handler for the SIGALRM and SIGINI signals */
    memset(&act, 0, sizeof(act));
    act.sa_handler = &doping;
    sigaction(SIGALRM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    // Host resolve domain name service
    hostent *h = gethostbyname(host);
    hostname = h->h_name;
    ipadrr = inet_ntoa(*(struct in_addr *)(h->h_addr));

    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int n = 1;

    if (s == -1)
    {
        LOG_D(TAG, "create socket fd failed. errno: %d", errno);
        if (errno == EPERM)
        {
            LOG_D(TAG, "Operation not permitted");
        }
        if (errno == EACCES)
        {
            LOG_D(TAG,
                  "Permission to create a socket of the specified type and/or protocol is denied");
        }
        exit(errno);
    }

    setuid(getuid());

    // Set broadcast
    int on = 1;
    if ((setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) == -1)
    {
        LOG_D(TAG, "[setsockopt] SO_BROADCAST errno: %d", errno);
    }
    // Set buffer
    int size = 60 * 1024;
    if ((setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) == -1)
    {
        LOG_D(TAG, "[setsockopt] SO_RCVBUF errno: %d", errno);
    }

    /* Starting a timer to send the SIGALRM signal */
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 1;
    /* Timer first every second */
    timer.it_interval.tv_sec = 1;
    timer.it_interval.tv_usec = 0;
    /* Starting the real-time timer */
    setitimer(ITIMER_REAL, &timer, NULL);

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr = *((struct in_addr *)h->h_addr);

    // Receive from
    int bytes = 0;
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[BUFFER_SIZE];

    while (1)
    {
        bytes = recvfrom(s,
                         buffer,
                         sizeof(buffer),
                         0,
                         (struct sockaddr *)&from,
                         &from_len);
        if (bytes < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOG_D(TAG, "recvfrom() failed");
            continue;
        }
        gettimeofday(&tval, NULL);
        LOG_D(TAG, "%d bytes from %s", bytes, ipadrr);
    }
}

void doping(int signal)
{
    if (signal != SIGALRM || step >= max)
    {
        exit(1);
    }
    int icmplen;
    struct icmp *icmp;
    char sendbuf[BUFFER_SIZE];
    icmp = reinterpret_cast<struct icmp *>(sendbuf);
    /* Fill all filed of the ICMP message */
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = getpid();
    icmp->icmp_seq = step;
    gettimeofday((struct timeval *)icmp->icmp_data, NULL);

    icmplen = 8 + 56;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum(reinterpret_cast<unsigned short *>(icmp), icmplen);

    if (sendto(
            s,
            sendbuf,
            icmplen,
            0,
            reinterpret_cast<sockaddr *>(&serveraddr),
            sizeof(sockaddr)) < 0)
    {
        LOG_D(TAG, "[send to] error: %d", errno);
    }

    if (step == 0)
    {
        LOG_D(TAG, "PING %s (%s): %d data bytes", hostname, ipadrr, icmplen);
    }

    step++;
}

}; // namespace NetUtility

int main()
{
    NetUtility::ping("jiyang.site", 6);
    return 0;
}