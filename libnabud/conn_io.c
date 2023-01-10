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

/*
 * Connection I/O abstraction.
 *
 * Shared by NABU connections and control connections.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "conn_io.h"
#include "log.h"

/* Huh, some platforms don't define INFTIM. */
#ifndef INFTIM
#define	INFTIM		-1
#endif

static pthread_mutex_t conn_io_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conn_io_list_cv = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(, conn_io) conn_io_list = LIST_HEAD_INITIALIZER(conn_io_list);

static void
conn_io_insert(struct conn_io *conn)
{
	assert(! conn->on_list);

	pthread_mutex_lock(&conn_io_list_mutex);
	LIST_INSERT_HEAD(&conn_io_list, conn, link);
	conn->on_list = true;
	pthread_cond_signal(&conn_io_list_cv);
	pthread_mutex_unlock(&conn_io_list_mutex);
}

static void
conn_io_remove(struct conn_io *conn)
{
	if (conn->on_list) {
		pthread_mutex_lock(&conn_io_list_mutex);
		LIST_REMOVE(conn, link);
		conn->on_list = false;
		pthread_cond_signal(&conn_io_list_cv);
		pthread_mutex_unlock(&conn_io_list_mutex);
	}
}

/*
 * conn_io_shutdown --
 *	Cancel all connections.
 */
void
conn_io_shutdown(void)
{
	struct conn_io *conn, *nconn;

	pthread_mutex_lock(&conn_io_list_mutex);
	LIST_FOREACH_SAFE(conn, &conn_io_list, link, nconn) {
		conn_io_cancel(conn);
	}
	while (LIST_FIRST(&conn_io_list) != NULL) {
		pthread_cond_wait(&conn_io_list_cv, &conn_io_list_mutex);
	}
	pthread_mutex_unlock(&conn_io_list_mutex);
}

/*
 * conn_io_set_nbio --
 *	Set non-blocking I/O on the specified file descriptor.
 */
static bool
conn_io_set_nbio(struct conn_io *conn, const char *which, int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		log_error("[%s] fcntl(F_GETFL) on %s failed: %s",
		    conn->name, which, strerror(errno));
		return false;
	}
	if ((flags & O_NONBLOCK) == 0) {
		flags |= O_NONBLOCK;
		if (fcntl(fd, F_SETFL) < 0) {
			log_error("[%s] fcntl(F_SETFL) on %s failed: %s",
			    conn->name, which, strerror(errno));
			return false;
		}
	}
	return true;
}

/*
 * conn_io_init --
 *	Initialize a conn_io.
 */
bool
conn_io_init(struct conn_io *conn, char *name, int fd)
{
	assert(name != NULL);
	conn->name = name;

	conn->fd = fd;
	conn->cancel_fds[0] = conn->cancel_fds[1] = -1;

	/*
	 * Create the pipe that's used for connection cancellation.
	 * The read side is marked non-blocking so that we can safely
	 * drain it if the connection is restarted.
	 */
	if (pipe(conn->cancel_fds) < 0) {
		log_error("[%s] pipe() failed: %s", conn->name,
		    strerror(errno));
		goto bad;
	}
	if (! conn_io_set_nbio(conn, "cancel pipe", conn->cancel_fds[0])) {
		/* Error already logged. */
		goto bad;
	}

	/*
	 * Set non-blocking I/O on the connection endpoint descriptor.
	 */
	if (! conn_io_set_nbio(conn, "connection endpoint", conn->fd)) {
		/* Error already logged. */
		goto bad;
	}

	conn_io_insert(conn);
	return true;

 bad:
	conn_io_fini(conn);
	return false;
}

/*
 * conn_io_start --
 *	Start a conn_io.
 */
bool
conn_io_start(struct conn_io *conn, void *(*func)(void *), void *arg)
{
	pthread_attr_t attr;
	int error;

	if (func != NULL) {
		/*
		 * Create the thread that handles the connection.
		 */
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		error = pthread_create(&conn->thread, &attr, func, arg);
		if (error) {
			log_error("[%s] pthread_create() failed: %s",
			    conn->name, strerror(error));
			return false;
		}
	}
	return true;
}

/*
 * conn_io_fini --
 *	Tear down a conn_io.
 */
void
conn_io_fini(struct conn_io *conn)
{
	conn_io_remove(conn);

	/* close the writer first because SIGPIPE is super annoying. */
	if (conn->cancel_fds[1] != -1) {
		close(conn->cancel_fds[1]);
	}
	if (conn->cancel_fds[0] != -1) {
		close(conn->cancel_fds[0]);
	}
	if (conn->fd != -1) {
		close(conn->fd);
	}
	if (conn->name != NULL) {
		free(conn->name);
	}
}

/*
 * conn_io_accept --
 *	Wait for a connection and accept it.
 */
bool
conn_io_accept(struct conn_io *conn, struct sockaddr *peersa,
    socklen_t *peersalenp, int *sockp)
{
	/* Never a deadline for these. */
	static const struct timespec deadline = { 0, 0 };

 again:
	if (! conn_io_wait(conn, &deadline, true)) {
		if (conn_io_state(conn) == CONN_STATE_CANCELLED) {
			log_info("[%s] Received cancellation request.",
			    conn_io_name(conn));
		}
		return false;
	}
	*sockp = accept(conn->fd, peersa, peersalenp);
	if (*sockp < 0) {
		if (errno != EAGAIN) {
			log_error("[%s] accept() failed: %s",
			    conn_io_name(conn), strerror(errno));
			conn_io_set_state(conn, CONN_STATE_ABORTED);
			return false;
		}
		goto again;
	}
	return true;
}

/*
 * conn_io_deadline --
 *	Calculate the deadline for an I/O transaction.
 */
static void
conn_io_deadline(const struct conn_io *conn, struct timespec *deadline)
{
	if (conn->watchdog == 0) {
		deadline->tv_sec = 0;
		deadline->tv_nsec = 0;
	} else {
		if (clock_gettime(CLOCK_MONOTONIC, deadline) < 0) {
			log_fatal(
			    "[%s] clock_gettime(CLOCK_MONOTONIC) failed: %s",
			    conn->name, strerror(errno));
		}
		deadline->tv_sec += conn->watchdog;
	}
}

#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (/* CONSTCOND */ 0)

#define	timespec2ns(x)	(((uint64_t)(x)->tv_sec) * 1000000000L + (x)->tv_nsec)

/*
 * conn_io_polltimo --
 *	Calculate the timeout value to pass to poll(), considering
 *	the current deadline.
 */
int
conn_io_polltimo(struct conn_io *conn, const struct timespec *deadline,
    bool is_recv)
{
	struct timespec now, timo;
	const char *which = is_recv ? "recv" : "send";

	if (deadline->tv_sec == 0 && deadline->tv_nsec == 0) {
		log_debug("[%s] No %s deadline, returning INFTIM.", conn->name,
		    which);
		return INFTIM;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		log_fatal("[%s] clock_gettime(CLOCK_MONOTONIC) failed: %s",
		    conn->name, strerror(errno));
	}

	timespecsub(deadline, &now, &timo);
	if (timo.tv_sec < 0 ||
	    (timo.tv_sec == 0 && timo.tv_nsec <= 0)) {
		/* Deadline has passed. */
		log_debug(
		    "[%s] Deadline for %s has passed, returning 0 ms.",
		    conn->name, which);
		return 0;
	}

	/*
	 * Convert to milliseconds for poll(), clamp to a reasonable
	 * value, and ensure that, since there is some time left, that
	 * we allow it to actually wait.
	 */
	uint64_t millis = timespec2ns(&timo) / 1000000;
	if (millis > 1 * 60 * 1000) {
		millis = 1 * 60 * 1000;	/* 1 minute */
	} else if (millis == 0) {
		millis = 1;
	}
	log_debug("[%s] next %s timeout: %d ms", which, conn->name,
	    (int)millis);
	return (int)millis;
}

/*
 * conn_io_wait --
 *	Wait to be able to do I/O on a connection.
 */
bool
conn_io_wait(struct conn_io *conn, const struct timespec *deadline,
    bool is_recv)
{
	short pollwhich = is_recv ? POLLIN : POLLOUT;
	struct pollfd fds[2] = {
		[0] = {
			.fd = conn->fd,
			.events = pollwhich | POLLERR | POLLHUP | POLLNVAL,
		},
		[1] = {
			.fd = conn->cancel_fds[0],
			.events = POLLIN | POLLERR | POLLHUP | POLLNVAL,
		},
	};
	int pollret;
	const char *which = is_recv ? "recv" : "send";

	pollret = poll(fds, 2, conn_io_polltimo(conn, deadline, is_recv));
	if (pollret < 0) {
		log_error("[%s] poll() for %s failed: %s", conn->name,
		    which, strerror(errno));
		conn->state = CONN_STATE_ABORTED;
		return false;
	}
	if (pollret == 0) {
		log_info("[%s] Connection (%s) timed out.", conn->name, which);
		conn->state = CONN_STATE_ABORTED;
		return false;
	}
	if (fds[1].revents) {
		if (fds[1].revents & POLLIN) {
			log_debug("[%s] Connection cancelled.", conn->name);
			return false;
		}
		log_fatal("[%s] %s fds[1].revents = 0x%04x", conn->name,
		    which, fds[1].revents);
		/* NOTREACHED */
	}
	if (fds[0].revents == 0) {
		log_fatal("[%s] %s fds[0].revents == 0", conn->name, which);
		/* NOTREACHED */
	}
	if (fds[0].revents & pollwhich) {
		/* We can do I/O, woo! */
		return true;
	}
	log_error("[%s] Connection failure in %s: fds[0].revents = 0x%04x.",
	    conn->name, which, fds[0].revents);
	conn->state = CONN_STATE_ABORTED;
	return false;
}

/*
 * conn_io_send --
 *	Send data on the connection.  Will wait indefinitely for
 *	all data to be sent unless the connection watchdog is
 *	enabled.
 */
void
conn_io_send(struct conn_io *conn, const void *vbuf, size_t len)
{
	const uint8_t *buf = vbuf;
	struct timespec deadline;
	const uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		/* Wait for the connection to accept writes. */
		if (! conn_io_wait(conn, &deadline, false)) {
			/* Error already logged. */
			return;
		}

		actual = write(conn->fd, curptr, resid);
		if (actual < 0 && errno != EAGAIN) {
			log_error("[%s] write() failed: %s", conn->name,
			    strerror(errno));
			conn->state = CONN_STATE_ABORTED;
			return;
		}
		if (actual == 0) {
			log_debug("[%s] Got End-of-File", conn->name);
			conn->state = CONN_STATE_EOF;
			return;
		}

		resid -= actual;
		curptr += actual;
		if (resid == 0) {
			return;
		}
	}
}

/*
 * conn_io_send_byte --
 *	Convenience wrapper around conn_io_send() that handles
 *	sending just a single byte.
 */
void
conn_io_send_byte(struct conn_io *conn, uint8_t val)
{
	return conn_io_send(conn, &val, 1);
}

/*
 * conn_io_recv --
 *	Receive data on the connection.  Will wait indefinitely for
 *	all data to be received unless the connection watchdog is
 *	enabled.
 *
 *	N.B. We wait for ALL of the expected data to arrive.  There
 *	are no partial reads!
 */
bool
conn_io_recv(struct conn_io *conn, void *vbuf, size_t len)
{
	uint8_t *buf = vbuf;
	struct timespec deadline;
	uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		/* Wait for the connection to be ready for reads. */
		if (! conn_io_wait(conn, &deadline, true)) {
			/* Error already logged. */
			return false;
		}

		actual = read(conn->fd, curptr, resid);
		if (actual < 0 && errno != EAGAIN) {
			log_error("[%s] read() failed: %s", conn->name,
			    strerror(errno));
			conn->state = CONN_STATE_ABORTED;
			return false;
		}
		if (actual == 0) {
			log_debug("[%s] Got End-of-File", conn->name);
			conn->state = CONN_STATE_EOF;
			return false;
		}

		resid -= actual;
		curptr += actual;
		if (resid == 0) {
			return true;
		}
	}
}

/*
 * conn_io_recv_byte --
 *	Convenience wrapper around conn_io_recv() that handles
 *	receiving just a single byte.
 */
bool
conn_io_recv_byte(struct conn_io *conn, uint8_t *val)
{
	return conn_io_recv(conn, val, 1);
}

/*
 * conn_io_start_watchdog --
 *	Enable the watchdog timer on this connection.
 */
void
conn_io_start_watchdog(struct conn_io *conn, unsigned int timo_sec)
{
	conn->watchdog = timo_sec;
}

/*
 * conn_io_stop_watchdog --
 *	Disable the watchdog timer on this connection.
 */
void
conn_io_stop_watchdog(struct conn_io *conn)
{
	conn->watchdog = 0;
}

/*
 * conn_io_cancel --
 *	Cancel a connection.
 */
void
conn_io_cancel(struct conn_io *conn)
{
	/*
	 * Mark the connection as cancelled and wake any threads
	 * waiting to do I/O.
	 */
	conn_io_set_state(conn, CONN_STATE_CANCELLED);
	if (write(conn->cancel_fds[1], &conn->state, sizeof(conn->state)) < 0) {
		log_error("[%s] Connection cancellation failed!",
		    conn_io_name(conn));
	}
}
