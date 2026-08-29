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

#ifndef PAYMENT_CHANNEL_WIRE_H
#define PAYMENT_CHANNEL_WIRE_H

#include "channel.h"

/* One envelope per line over a plain TCP socket, in the clear.
 *
 * A real deployment needs a transport with authentication and confidentiality,
 * because an active attacker on this socket can substitute Bob's pubkey during
 * the announce and take the channel. That is a transport problem, deliberately
 * out of scope here: this is the smallest thing that lets the two programs
 * exchange the protocol so it can be watched and driven against a node. */

/* Listen on (host):(port). Returns a listening fd, or -1. */
int pc_wire_listen(const char *host, int port);

/* Accept one connection. Returns a connected fd, or -1. */
int pc_wire_accept(int listen_fd);

/* Connect to (host):(port). Returns a connected fd, or -1. */
int pc_wire_connect(const char *host, int port);

/* Send one envelope, newline-terminated. Returns 1 on success. */
int pc_wire_send(int fd, const pc_envelope *env);

/* Read one envelope. Returns 1 on success, 0 on clean EOF, -1 on error or on a
 * line this protocol does not accept. */
int pc_wire_recv(int fd, pc_envelope *env);

/* Split "host:port"; port may be omitted and defaults to (defport). */
int pc_wire_split(const char *hostport, char *host, size_t hostcap, int defport);

#endif /* PAYMENT_CHANNEL_WIRE_H */
