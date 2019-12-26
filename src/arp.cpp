#include <sys/socket.h>
#include "log.h"
#include "address_util.cpp"
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <unistd.h>

/* Usage:
 * ./arp [host]
 * eg: ./arp 192.168.0.1
*/

namespace NetUtility
{

#define TAG "ARP"

int openBpf();
int setupBpf(int fd, const char *ifname);
int getAddrs(struct sockaddr_in *protocolAddr, u_char *hardwareAddr);
void outputArp(const struct arphdr *header);
void outputHardwareAddress(const u_char *head, int len);
void outputProtocolAddress(const char *head, int len);
void readBpf(int fd);

int openBpf()
{
    char _buf[32];
    int bfd = -1;
    int i = 0;
    // find a useable bpf fd
    for (i = 0; i < 255; i++)
    {
        snprintf(_buf, sizeof(_buf), "/dev/bpf%u", i);
        bfd = open(_buf, O_RDWR);
        if (bfd > 0)
        {
            break;
        }
    }
    return bfd;
}

int setupBpf(int fd, const char *ifname)
{
    struct ifreq request;

    strlcpy(request.ifr_name, ifname, sizeof(request.ifr_name) - 1);
    /* (struct ifreq) Returns the name of the hardware interface that the file is listening on.  The name is returned in the ifr_name field of the ifreq structure.  All other fields are undefined */
    int resp = ioctl(fd, BIOCSETIF, &request);
    if (resp < 0)
    {
        perror("BIOCSETIF failed: ");
        return -1;
    }

    /* (u_int) Returns the type of the data link layer underlying the attached interface.  EINVAL is returned if no interface has been specified.  The device types, prefixed with ``DLT_'', are defined in <net/bpf.h>. */
    u_int type;
    if (ioctl(fd, BIOCGDLT, &type) < 0)
    {
        perror("BIOCGDLT failed: ");
        return -1;
    }

    if (type != DLT_EN10MB)
    {
        printf("unsupported datalink type\n");
        return -1;
    }

    // u_int tstamp;
    // tstamp = BPF_T_NANOTIME;

    // if (ioctl(fd, BIOCSTSTAMP, &tstamp) < 0)
    // {
    //     perror("BIOCSTSTAMP faild: ");
    //     return -1;
    // }

    int enable = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &enable) < 0)
    {
        perror("BIOCSIMMEDIATE failed: ");
        return -1;
    }
    return 0;
}

void arp(const char *host)
{
    sockaddr_in targetaddr = getsockaddrbyhost(host);
    LOG_D(TAG, "target: %s", inet_ntoa(targetaddr.sin_addr));

    struct sockaddr_in protocolAddr;
    struct sockaddr_dl hardwarAddr;
    u_char senderHardwareAddress[ETHER_ADDR_LEN];
    if (getAddrs(&protocolAddr, senderHardwareAddress) < 0)
    {
        perror("[getAddrs]");
        exit(1);
    }

    /* ether_header: 14, arp_header: 28 */
    int etherSize = 14;
    int arpSize = 28;
    int packSize = etherSize + arpSize;
    char buf[packSize];
    bzero(buf, sizeof(buf));

    ether_header_t *eaddr = (ether_header_t *)buf;
    static const u_char etherBroadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eaddr->ether_dhost, etherBroadcast, 6);
    eaddr->ether_type = htons(ETHERTYPE_ARP);
    struct arphdr *arphdr = (struct arphdr *)(buf + etherSize);
    // 硬件类型
    arphdr->ar_hrd = htons(ARPHRD_ETHER);
    // 协议类型
    arphdr->ar_pro = htons(ETHERTYPE_IP);
    // 硬件地址长度
    arphdr->ar_hln = sizeof(senderHardwareAddress);
    // 协议地址长度
    arphdr->ar_pln = sizeof(targetaddr.sin_addr);
    // 操作码
    arphdr->ar_op = htons(ARPOP_REQUEST);
    int offset = sizeof(arphdr->ar_hrd) +
                 sizeof(arphdr->ar_pro) +
                 sizeof(arphdr->ar_op) +
                 sizeof(arphdr->ar_hln) +
                 sizeof(arphdr->ar_pln) + etherSize;
    // 源硬件地址
    memcpy(buf + offset, senderHardwareAddress, ETHER_ADDR_LEN);
    offset += ETHER_ADDR_LEN;
    // 源协议地址
    memcpy(buf + offset, &(protocolAddr.sin_addr), 4);
    offset += 4;
    // 目标硬件地址
    memset(buf + offset, 0, ETHER_ADDR_LEN);
    offset += ETHER_ADDR_LEN;
    // 目标协议地址
    memcpy(buf + offset, &(targetaddr.sin_addr), 4);

    outputArp(arphdr);

    int bfd = openBpf();
    if (bfd < 0)
    {
        LOG_D(TAG, "[openBpf] failed");
        exit(1);
    }

    setupBpf(bfd, "en0");

    ssize_t writed = write(bfd, buf, packSize);
    if (writed < 0)
    {
        perror("writev failed.");
    }
    else
    {
        LOG_D(TAG, "writed %d", writed);
        readBpf(bfd);
    }

    close(bfd);
}

void readBpf(int fd)
{
    int bufSize;
    /* Returns the required buffer length for reads on bpf files */
    if (ioctl(fd, BIOCGBLEN, &bufSize) < 0)
    {
        perror("BIOCGBLEN failed: ");
        exit(1);
    }
    LOG_D(TAG, "BIO Buffer: %d", bufSize);
    char re[bufSize];

    int finish = 1;
    while (finish)
    {
        ssize_t readed = read(fd, re, bufSize);
        if (readed < 0)
        {
            perror("read failed.");
            break;
        }
        else if (readed == 0)
        {
            LOG_D(TAG, "read end.");
            break;
        }
        LOG_D(TAG, "read %d bytes data.", readed);

        const struct bpf_hdr *bpfHeader = (struct bpf_hdr *)re;
        LOG_D(TAG, "bpf header tstamp: %", bpfHeader->bh_tstamp);
        LOG_D(TAG, "bpf header len: %d", bpfHeader->bh_hdrlen);
        LOG_D(TAG, "bpf header data len: %d", bpfHeader->bh_datalen);
        LOG_D(TAG, "bpf header cap len: %d", bpfHeader->bh_caplen);
        ether_header_t *eaddr = (ether_header_t *)(re + bpfHeader->bh_hdrlen);

        u_short etherType = ntohs(eaddr->ether_type);
        if (etherType == ETHERTYPE_ARP)
        {
            LOG_D(TAG, "Received ARP");
            const struct arphdr *arp = (struct arphdr *)(re + bpfHeader->bh_hdrlen + sizeof(ether_header_t));
            if (arp->ar_op == ntohs(ARPOP_REPLY))
            {
                LOG_D(TAG, "Received ARP Reply");
                outputArp(arp);
                finish = 0;
            }
        }
    }
}

int getAddrs(struct sockaddr_in *protocolAddr, u_char *hardwareAddr)
{
    struct ifaddrs *addrs, *addr;
    struct sockaddr_dl hardwareDl;
    if (getifaddrs(&addrs) < 0)
    {
        perror("[getifaddrs]");
        return -1;
    }
    addr = addrs;
    while (addr)
    {
        if (strcmp("en0", addr->ifa_name) == 0 && addr->ifa_addr->sa_family == AF_INET)
        {
            memcpy(protocolAddr, (struct sockaddr_in *)(addr->ifa_addr), sizeof(struct sockaddr_in));
        }
        if (strcmp("en0", addr->ifa_name) == 0 && addr->ifa_addr->sa_family == AF_LINK)
        {
            memcpy(&hardwareDl, (struct sockaddr_dl *)(addr->ifa_addr), sizeof(struct sockaddr_dl));
        }
        addr = addr->ifa_next;
    }

    freeifaddrs(addrs);

    if (!protocolAddr || !hardwareAddr)
    {
        LOG_D(TAG, "not get ifaddrs");
        return -1;
    }
    memcpy(hardwareAddr, LLADDR(&hardwareDl), hardwareDl.sdl_alen);
    return 0;
}

void outputArp(const struct arphdr *header)
{
    LOG_D(TAG, "Hardware type: %d", ntohs(header->ar_hrd));
    LOG_D(TAG, "Protocol type: %d", ntohs(header->ar_pro));
    LOG_D(TAG, "Opereation code: %d", ntohs(header->ar_op));
    LOG_D(TAG, "Hardware address len: %d", header->ar_hln);
    LOG_D(TAG, "Protocol address len: %d", header->ar_pln);

    int offset = 8;
    std::cout << "Source hardware address: ";
    outputHardwareAddress((u_char *)header + offset, header->ar_hln);
    offset += header->ar_hln;

    std::cout << "Source ip address: ";
    outputProtocolAddress((char *)header + offset, header->ar_pln);
    offset += header->ar_pln;

    std::cout << "Dest hardware address: ";
    outputHardwareAddress((u_char *)header + offset, header->ar_hln);
    offset += header->ar_hln;

    std::cout << "Dest ip address: ";
    outputProtocolAddress((char *)header + offset, header->ar_pln);
}

void outputHardwareAddress(const u_char *head, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        /* ntohl: BigEndian -> LitterEndian  方便显示 */
        std::cout << std::showbase << std::hex << ntohl(head[i]);
        if (i < len - 1)
        {
            std::cout << ":";
        }
    }
    std::cout << std::endl;
}

void outputProtocolAddress(const char *head, int len)
{
    for (size_t i = 0; i < len; i++)
    {
        std::cout << std::dec << ((int)head[i] & 0xff);
        if (i < len - 1)
        {
            std::cout << ".";
        }
    }
    std::cout << std::endl;
}

} // namespace NetUtility

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        perror("Need host arg.");
        exit(1);
    }
    try
    {
        NetUtility::arp(argv[1]);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    return 0;
}