/*-
 * Copyright (c) 2022, 2023 Jason R. Thorpe.
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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "libnabud/conn_io.h"
#include "libnabud/nabu_proto.h"
#include "libnabud/nbsd_queue.h"

typedef enum {
	CONN_TYPE_INVALID	=	0,
	CONN_TYPE_LISTENER	=	1,
	CONN_TYPE_SERIAL	=	2,
	CONN_TYPE_TCP		=	3,
} conn_type;

struct nabu_segment;

struct nabu_connection {
	/* I/O context */
	struct conn_io	io;

	/* Link on the list of connections. */
	TAILQ_ENTRY(nabu_connection) link;
	bool		on_list;

	/* Type of this connection. */
	conn_type	type;

	/*
	 * The packet being sent is buffered here.  We double the
	 * size in case every byte needs to be escaped.
	 */
	uint8_t		pktbuf[NABU_MAXPACKETSIZE * 2];
	size_t		pktlen;

	/*
	 * This is set if we're being enumerated.  If we are,
	 * then we have to wait until the enumeration is complete
	 * before we can be removed from the connection list.
	 *
	 * This field is protected by the connection list mutex.
	 */
	uint32_t	enum_count;

	/*
	 * Root of this connection's local file storage.
	 */
	char		*file_root;

	/* Lock that protects the data below. */
	pthread_mutex_t mutex;

	/* Last image used. */
	struct nabu_image *l_last_image;

	/* Selected channel. */
	struct image_channel *l_channel;

	/* Selected file. */
	char *l_selected_file;
};

extern unsigned int conn_count;

void	conn_add_serial(char *, unsigned int);
void	conn_add_tcp(char *, unsigned int);
void	conn_destroy(struct nabu_connection *);

bool	conn_enumerate(bool (*)(struct nabu_connection *, void *), void *);

struct nabu_image *conn_get_last_image(struct nabu_connection *);
struct nabu_image *conn_set_last_image(struct nabu_connection *,
				       struct nabu_image *);
struct nabu_image *conn_set_last_image_if(struct nabu_connection *,
				       struct nabu_image *,
				       struct nabu_image *);

struct image_channel *conn_get_channel(struct nabu_connection *);
void	conn_set_channel(struct nabu_connection *, struct image_channel *);
char	*conn_get_selected_file(struct nabu_connection *);
void	conn_set_selected_file(struct nabu_connection *, char *);

#define	conn_name(c)		conn_io_name(&(c)->io)
#define	conn_state(c)		conn_io_state(&(c)->io)
#define	conn_set_state(c, s)	conn_io_set_state(&(c)->io, (s))

#define	conn_send(c, b, l)	conn_io_send(&(c)->io, (b), (l))
#define	conn_send_byte(c, b)	conn_io_send_byte(&(c)->io, (b))
#define	conn_recv(c, b, l)	conn_io_recv(&(c)->io, (b), (l))
#define	conn_recv_byte(c, b)	conn_io_recv_byte(&(c)->io, (b))

#define	conn_start_watchdog(c, t) conn_io_start_watchdog(&(c)->io, (t))
#define	conn_stop_watchdog(c)	conn_io_stop_watchdog(&(c)->io)

#define	conn_cancel(c)		conn_io_cancel(&(c)->io)

#endif /* conn_h_included */
