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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "nabu_proto.h"
#include "nbsd_queue.h"

typedef enum {
	CONN_TYPE_INVALID	=	0,
	CONN_TYPE_SERIAL	=	1,
} conn_type;

typedef enum {
	CONN_STATE_OK		=	0,
	CONN_STATE_EOF		=	1,
	CONN_STATE_CANCELLED	=	2,
	CONN_STATE_ABORTED	=	3,
} conn_state;

struct nabu_segment;

struct nabu_connection {
	/* Link on the list of connections. */
	LIST_ENTRY(nabu_connection) link;
	bool		on_list;

	/* Display name for this connection. */
	char		*name;

	/* Thread that owns this connection. */
	pthread_t	thread;

	/* File descriptor for this connection. */
	int		fd;

	/* I/O watchdog time. */
	unsigned int	watchdog;

	/* Our connection state. */
	conn_state	state;

	/*
	 * Pipe file descriptors used to wake threads blocked in poll()
	 * when the connection is cancelled.
	 */
	int		cancel_fds[2];

	/*
	 * The packet being sent is buffered here.  We double the
	 * size in case every byte needs to be escaped.
	 */
	uint8_t		pktbuf[NABU_MAXPACKETSIZE * 2];
	size_t		pktlen;

	/* RetroNet file API. */
	LIST_HEAD(, rn_file) rn_files;
	char		*rn_file_root;

	/* Lock that protects the data below. */
	pthread_mutex_t mutex;

	/* Last image used. */
	struct nabu_image *l_last_image;

	/* Selected channel. */
	struct image_channel *l_channel;
};

extern unsigned int conn_count;

void	conn_add_serial(char *, unsigned int);
void	conn_add_tcp(char *, unsigned int);
void	conn_destroy(struct nabu_connection *);

struct nabu_image *conn_get_last_image(struct nabu_connection *);
struct nabu_image *conn_set_last_image(struct nabu_connection *,
				       struct nabu_image *);
struct nabu_image *conn_set_last_image_if(struct nabu_connection *,
				       struct nabu_image *,
				       struct nabu_image *);

struct image_channel *conn_get_channel(struct nabu_connection *);
void	conn_set_channel(struct nabu_connection *, struct image_channel *);
char	*conn_selected_file(struct nabu_connection *);

void	conn_cancel(struct nabu_connection *);
void	conn_shutdown(void);

void	conn_send(struct nabu_connection *, const uint8_t *, size_t);
void	conn_send_byte(struct nabu_connection *, uint8_t);
bool	conn_recv(struct nabu_connection *, uint8_t *, size_t);
bool	conn_recv_byte(struct nabu_connection *, uint8_t *);

void	conn_start_watchdog(struct nabu_connection *, unsigned int);
void	conn_stop_watchdog(struct nabu_connection *);

#endif /* conn_h_included */
