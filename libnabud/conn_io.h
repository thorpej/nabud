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

#ifndef conn_io_h_included
#define	conn_io_h_included

#include <sys/socket.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "nbsd_queue.h"

typedef enum {
	CONN_STATE_OK		=	0,
	CONN_STATE_EOF		=	1,
	CONN_STATE_CANCELLED	=	2,
	CONN_STATE_ABORTED	=	3,
} conn_state;

struct conn_io {
	/* Link on the list of connections. */
	LIST_ENTRY(conn_io) link; 
	bool		on_list;

	/* The name/label for this connection. */
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
};

#define	conn_io_name(c)		(c)->name
#define	conn_io_state(c)	(c)->state
#define	conn_io_set_state(c, s)	(c)->state = (s)

bool	conn_io_init(struct conn_io *, char *, int);
bool	conn_io_start(struct conn_io *, void *(*)(void *), void *);
void	conn_io_fini(struct conn_io *);

int	conn_io_polltimo(struct conn_io *conn, const struct timespec *deadline,
	    bool is_recv);
bool	conn_io_wait(struct conn_io *, const struct timespec *deadline,
	    bool is_recv);

bool	conn_io_accept(struct conn_io *, struct sockaddr *, socklen_t *,
	    int *);

void	conn_io_send(struct conn_io *, const void *, size_t);
void	conn_io_send_byte(struct conn_io *, uint8_t);
bool	conn_io_recv(struct conn_io *, void *, size_t);
bool	conn_io_recv_byte(struct conn_io *, uint8_t *);

bool	conn_io_check_state(struct conn_io *);

void	conn_io_start_watchdog(struct conn_io *, unsigned int);
void	conn_io_stop_watchdog(struct conn_io *);

void	conn_io_cancel(struct conn_io *);
void	conn_io_shutdown(void);

#endif /* conn_io_h_included */
