//
// Example IGMP receiver to demonstrate networking problem with
// Parallels Destop 26.0.1 on MacOS 15.7 and MacOS 26.0.
//
// Notes:
// 1. The interface used for the test must be a real interface on a
//    network with IGMP activity. I.E. there should be an IGMP enabled
//    switch. You can confirm the presense of igmp activity by running:
//        tcpdump -i <interface> igmp
//    prior to running the test program.
// 2. Root priviledge is required to run the test proram because of the
//    need to create a raw socket.
//
// To run the test:
// 1. Compile this program as igmp-test:
//        cc igmp-test.c -o igmp-test
// 2. Without Parallels running, start igmp-test as root on the host,
//    specifying the interface to listen on, e.g.:
//        sudo ./igmp-test en0
// 3. igmp-test will sporaidically print "Received xx bytes" messages
//    as it receives IGMP packets from the router and other hosts in the
//    network (at least once per minute).
// 4. With igmp-test still running, start Parallels Desktop. It is not
//    necessary to start a virtual machine.
// 5. Note that igmp-test stops receiving IGMP packets. No packets will
//    be received while Parallels Desktop is running.
// 6. Stop Parallels Desktop.
// 7. Note that igmp-test starts receiving IGMP packets again.
//
// Whatever network bridge/filter Parallels is installing is interfering
// with receipt of raw IGMP packets reception on the host system.
//
// This is a bug in Parallels Desktop. Please bring this to the attemtion
// of the person or team responsible for the network bridge/filter.
//
// Thank you.
//


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
#include <netinet/igmp.h>
#include <sys/event.h>


int main(int argc, char *argv[])
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
    }
}
