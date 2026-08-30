/*

 The MIT License (MIT)

 Copyright (c) 2026 bluezr

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#include "wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* an open message carries the psbt and the funding transaction that created its
   input, so the line has to hold both fields plus the json frame */
#define PC_WIRE_TIMEOUT_SEC 30
#define PC_WIRE_MAX (2 * PC_MAX_PSBT_HEX + 512)

int pc_wire_split(const char *hostport, char *host, size_t hostcap, int defport)
{
    const char *colon = strrchr(hostport, ':');
    if (!colon) {
        if (snprintf(host, hostcap, "%s", hostport) < 0) return -1;
        return defport;
    }
    size_t hl = (size_t)(colon - hostport);
    if (hl + 1 > hostcap) return -1;
    memcpy(host, hostport, hl);
    host[hl] = '\0';
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    return port;
}

static int fill_addr(struct sockaddr_in *sa, const char *host, int port)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa->sin_addr) != 1) return 0;
    return 1;
}

int pc_wire_listen(const char *host, int port)
{
    struct sockaddr_in sa;
    if (!fill_addr(&sa, host, port)) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int pc_wire_accept(int listen_fd)
{
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) return -1;
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    /* a peer that connects and never finishes a line would otherwise hold the
       accept loop open for as long as it likes */
    {
        struct timeval tv = { PC_WIRE_TIMEOUT_SEC, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

int pc_wire_connect(const char *host, int port)
{
    struct sockaddr_in sa;
    if (!fill_addr(&sa, host, port)) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    /* a peer that connects and never finishes a line would otherwise hold the
       accept loop open for as long as it likes */
    {
        struct timeval tv = { PC_WIRE_TIMEOUT_SEC, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

static int write_all(int fd, const char *buf, size_t len)
{
    while (len) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (n == 0) return 0;
        buf += n;
        len -= (size_t)n;
    }
    return 1;
}

int pc_wire_send(int fd, const pc_envelope *env)
{
    char *line = (char *)malloc(PC_WIRE_MAX);
    if (!line) return 0;
    int ok = 0;
    if (pc_envelope_encode(env, line, PC_WIRE_MAX - 1) == PC_OK) {
        size_t n = strlen(line);
        line[n++] = '\n';
        ok = write_all(fd, line, n);
    }
    free(line);
    return ok;
}

/* One byte at a time. A message here is at most a few tens of kilobytes and
   arrives once per payment, so a read buffer would be state to get wrong for
   no measurable gain. */
static int read_line(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return n ? -1 : 0;      /* truncated line is an error */
        if (c == '\n') { buf[n] = '\0'; return 1; }
        if (c == '\r') continue;
        if (n + 1 >= cap) return -1;        /* oversized: drop the peer */
        buf[n++] = c;
    }
}

int pc_wire_recv(int fd, pc_envelope *env)
{
    char *line = (char *)malloc(PC_WIRE_MAX);
    if (!line) return -1;
    int rc = read_line(fd, line, PC_WIRE_MAX);
    if (rc == 1 && pc_envelope_decode(line, env) != PC_OK) rc = -1;
    free(line);
    return rc;
}
