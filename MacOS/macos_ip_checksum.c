
//
// Copyright (c) 2025, Denny Page
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <netinet/igmp.h>
#include <sys/event.h>




// Calculate an internet checksum
uint16_t inet_csum(
    uint16_t *                  addr,
    int                         len)
{
    uint32_t                    sum = 0;
    uint16_t                    answer;

    // Sum all 16-bit words
    while (len > 1)
    {
        sum += *addr++;
        len -= sizeof(*addr);
    }

    // Add the remaining byte, if any
    if (len == 1)
    {
        sum += *(uint8_t *) addr;
    }

    // Add carries from the upper 16 bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // One's complement
    answer = (uint16_t) ~sum;

    return answer;
}


int main(
    int                         argc,
    char                        *argv[])
{
    char *                      ifname = argv[1];
    struct sockaddr_in          sin;
    unsigned int                if_index;
    int                         sock;

    int                         event_fd;
    struct kevent               event;
    struct kevent *             events;
    int                         num_events;
    ssize_t                     bytes;

    struct ip *                 ip;
    struct igmp *               igmp;
    int                         ip_header_len;
    ssize_t                     igmp_len;
    uint16_t                    original_csum;
    uint16_t                    calculated_csum;
    char                        addr_str[INET_ADDRSTRLEN];

    int                         r;
    char                        packet_buffer[65536];


    // Parse the command line
    if (argc != 2)
    {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    // Get the interface index
    if_index = if_nametoindex(ifname);
    if (if_index == 0)
    {
        printf("interface \"%s\" does not exist\n", ifname);
        exit(1);
    }

    // Create the socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (sock == -1)
    {
        printf("socket: %s\n", strerror(errno));
        exit(1);
    }

    // Bind the socket
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    r = bind(sock, (struct sockaddr *) &sin, sizeof(sin));
    if (r == -1)
    {
        printf("bind: %s\n", strerror(errno));
        exit(1);
    }

    // Set non-blocking
    (void) fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    // Create the kernel event notifier
    event_fd = kqueue();
    if (event_fd < 0)
    {
        printf("kqueue: %s\n", strerror(errno));
        exit(1);
    }

    // Add the sockets to the event notifier
    events = calloc(1, sizeof(struct kevent));
    if (events == NULL)
    {
        printf("calloc: %s\n", strerror(errno));
        exit(1);
    }

    EV_SET(&event, sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
    r = kevent(event_fd, &event, 1, NULL, 0, NULL);
    if (r < 0)
    {
        printf("kevent (EV_SET): %s\n", strerror(errno));
        exit(1);
    }

    // Loop forever waiting for events
    while (1)
    {
        num_events = kevent(event_fd, NULL, 0, events, 1, NULL);
        if (num_events < 0)
        {
            printf("kevent: %s\n", strerror(errno));
            exit(1);
        }

        // Receive the packet
        bytes = recvfrom(sock, packet_buffer, sizeof(packet_buffer), 0, NULL, NULL);
        if (bytes == -1)
        {
            printf("recvfrom: %s\n", strerror(errno));
            continue;
        }

        printf("Received %zd bytes\n", bytes);

        // Grab the IP header
        ip = (struct ip *) packet_buffer;
        ip_header_len = ip->ip_hl << 2;

        inet_ntop(AF_INET, &ip->ip_src, addr_str, sizeof(addr_str));
        printf("ip src:    %s\n", addr_str);

        inet_ntop(AF_INET, &ip->ip_dst, addr_str, sizeof(addr_str));
        printf("ip dst:    %s\n", addr_str);

#if defined(__APPLE__)
        // MacOS carries an old BSD bug where the ip_len field is stored in host
        // byte order, and has had the length of the ip header itself removed.
        // This must be reversed for the IP checksum to work correctly.
        ip->ip_len = htons(ip_header_len + ip->ip_len);
#endif

        printf("ip hl:     %d\n", ip->ip_hl << 2);
        printf("ip len:    %d\n", ntohs(ip->ip_len));
        printf("ip off:    %d\n", ntohs(ip->ip_off) & 0x1fff);
        printf("ip flags:  0x%04x\n", ntohs(ip->ip_off) & 0xe000);
        printf("ip csum:   0x%04x\n", ip->ip_sum);
        calculated_csum = inet_csum((uint16_t *) ip, ip_header_len);
        if (calculated_csum != 0)
        {
            // Reset the packet
            ip->ip_sum = 0;
            calculated_csum = inet_csum((uint16_t *) ip, ip_header_len);
            printf("IP checksum error: checksum should be 0x%04x\n", calculated_csum);
        }

        // Sanity check
        if (ip_header_len + sizeof(struct igmp) > bytes)
        {
            printf("IP packet too short (%lu bytes) for IGMP\n", bytes);
            continue;
        }

        // Grab the IGMP header
        igmp = (struct igmp *) (packet_buffer + ip_header_len);
        igmp_len = bytes - ip_header_len;
        printf("igmp len:  %zd\n", igmp_len);
        printf("igmp type: %02x\n", igmp->igmp_type);
        printf("igmp code: %d\n", igmp->igmp_code);
        printf("igmp csum: 0x%04x\n", igmp->igmp_cksum);
        printf("igmp grp:  %s\n", inet_ntoa(igmp->igmp_group));

        original_csum = igmp->igmp_cksum;
        igmp->igmp_cksum = 0;
        calculated_csum = inet_csum((uint16_t *) igmp, igmp_len);
        if (original_csum != calculated_csum)
        {
            printf("IGMP checksum error: checksum should be 0x%04x\n", calculated_csum);
        }

        printf("\n");
    }
}
