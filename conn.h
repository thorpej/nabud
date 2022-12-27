/*-
 * Copyright (c) 2022 Jason R. Thorpe.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef conn_h_included
#define	conn_h_included

#include <stdbool.h>
#include <stdint.h>

#include "nabu_proto.h"

struct nabu_connection {
	/* Next on the list of connections. */
	struct nabu_connection *next;
	bool		on_list;

	/* Display name for this connection. */
	char		*name;

	/* File descriptor for this connection. */
	int		fd;

	/* I/O watchdog time. */
	unsigned int	watchdog;

	/* True if we've been cancelled and should exit from the event loop. */
	bool		cancelled;

	/*
	 * Pipe file descriptors used to wake threads blocked in poll()
	 * when the connection is cancelled.
	 */
	int		cancel_fds[2];

	/* True if an error occurs that causes us to abourt the connection. */
	bool		aborted;

	/* Selected channel. */
	uint16_t	channel;
	bool		channel_valid;

	/*
	 * The packet being sent is buffered here.  We double the
	 * size in case every byte needs to be escaped.
	 */
	uint8_t		pktbuf[NABU_MAXPACKETSIZE * 2];
	size_t		pktlen;
};

extern unsigned int conn_count;

struct nabu_connection *conn_create_serial(const char *);
void	conn_destroy(struct nabu_connection *);

void	conn_cancel(struct nabu_connection *);
void	conn_shutdown(void);

void	conn_send(struct nabu_connection *, const uint8_t *, size_t);
void	conn_send_byte(struct nabu_connection *, uint8_t);
bool	conn_recv(struct nabu_connection *, uint8_t *, size_t);

void	conn_start_watchdog(struct nabu_connection *, unsigned int);
void	conn_stop_watchdog(struct nabu_connection *);

#endif /* conn_h_included */