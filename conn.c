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
 * Connection abstraction.
 *
 * Connections can be either over a serial interface to a real NABU,
 * but eventually also be over a socket to support NABU emulators.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "conn.h"
#include "log.h"

static bool
conn_set_nbio(struct nabu_connection *conn, const char *which, int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		log_error("[%s] fcntl(F_GETFL) on %s failed: %s",
		    conn->name, which, strerror(errno));
		return false;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL) < 0) {
		log_error("[%s] fcntl(F_SETFL) on %s failed: %s",
		    conn->name, which, strerror(errno));
		return false;
	}
	return true;
}

static const struct nabu_connection *
conn_create_common(const char *name, int fd)
{
	struct nabu_connection *conn;
	int flags;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		log_error("[%s] Unable to allocate connection structure.",
		    name);
		close(fd);
		return NULL;
	}
	conn->fd = fd;
	conn->cancel_fds[0] = conn->cancel_fds[1] = -1;

	conn->name = strdup(name);
	if (conn->name == NULL) {
		log_error("[%s] Unable to allocate connection name.", name);
		goto bad;
	}

	/*
	 * Create the pipe that's used for connection cancellation.
	 * The read side is marked non-blocking so that we can safely
	 * drain it if the connection is restarted.
	 */
	if (pipe(conn->cancel_fds) < 0) {
		log_error("[%s] pipe() failed: %s", name, sterror(errno));
		goto bad;
	}
	if (! conn_set_nbio(conn, "cancel pipe", conn->cancel_fds[0])) {
		/* Error already logged. */
		goto bad;
	}

	/*
	 * Set non-blocking I/O on the connection endpoint descriptor.
	 */
	if (! conn_set_nbio(conn, "connection endpoint", conn->fd)) {
		/* Error already logged. */
		goto bad;
	}

	return conn;

 bad:
	conn_destroy(conn);
	return NULL;
}

struct nabu_connection *
conn_create_serial(const char *path)
{
	return NULL;		/* XXX */
}

/*
 * conn_destroy --
 *	Destroy a connection structure.
 */
void
conn_destroy(struct nabu_connection *conn)
{
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

	free(conn);
}

/*
 * conn_cancel --
 *	Cancel a connection.
 */
void
conn_cancel(struct nabu_connection *conn)
{
	/*
	 * Mark the connection as cancelled and wake any threads
	 * waiting to do I/O.
	 */
	conn->cancelled = true;
	(void) write(conn->cancel_fds[1], &conn->cancelled,
	    sizeof(conn->cancelled));
}

/*
 * conn_io_deadline --
 *	Calculate the deadline for an I/O transaction.
 */
static void
conn_io_deadline(const struct nabu_connection *conn, struct timespec *deadline)
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
static int
conn_io_polltimo(const struct timespec *deadline)
{
	struct timespec now, timo;

	if (deadline->tv_sec == 0 && deadline->tv_nsec == 0) {
		return INFTIM;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		log_fatal(
		    "[%s] clock_gettime(CLOCK_MONOTONIC) failed: %s",
		    conn->name, strerror(errno));
	}

	timespecsub(deadline, &now, &timo);
	if (timo.tv_sec < 0 ||
	    (timo.tv_sec == 0 && timo.tv_nsec <= 0)) {
		/* Deadline has passed. */
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
	return (int)millis;
}

/*
 * conn_io_wait --
 *	Wait to be able to do I/O on a connection.
 */
static bool
conn_io_wait(struct nabu_connection *conn, bool is_recv)
{
	struct timespec deadline;
	struct pollfd fds[2] = {
		[0] = {
			.fd = conn->fd,
			.events = POLLWRNORM | POLLERR | POLLHUP | POLLNVAL,
		},
		[1] = {
			.fd = conn->cancel_fds[0],
			.events = POLLRDNORM | POLLERR | POLLHUP | POLLNVAL,
		},
	};
	int pollret;
	short pollwhich = is_recv ? POLLRDNORM : POLLWRNORM;
	const char *which = is_recv ? "recv" : "send";

	pollret = poll(fds, 2, conn_io_polltimo(&deadline));
	if (pollret < 0) {
		log_error("[%s] poll() for %s failed: %s", conn->name,
		    which, strerror(errno));
		conn->aborted = true;
		return false;
	}
	if (pollret == 0) {
		log_info("[%s] Connection (%s) timed out.", conn->name,
		    which);
		conn->aborted = true;
		return false;
	}
	if (fds[1].revents) {
		if (fds[1].revents & POLLRDNORM) {
			log_info("[%s] Connection cancelled.",
			    conn->name);
			return false;
		}
		log_fatal("[%s] fds[1].revents = 0x%04x", conn->name,
		    fds[1].revents);
		/* NOTREACHED */
	}
	if (fds[0].revents == 0) {
		log_fatal("[%s] (%s) fds[0].revents == 0", conn->name, which);
		/* NOTREACHED */
	}
	if (fds[0].revents & pollwhich) {
		/* We can do I/O, woo! */
		return true;
	}
	log_error("[%s] Connection failure in %s.", conn->name, which);
	conn->aborted = true;
	return false;
}

/*
 * conn_send --
 *	Send data on the connection.  Will wait indefinitely for
 *	all data to be sent unless the connection watchdog is
 *	enabled.
 */
void
conn_send(struct nabu_connection *conn, const uint8_t *buf, size_t len)
{
	const uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		actual = write(conn->fd, curptr, resid);
		if (actual < 0) {
			log_error("[%s] write() failed: %s", conn->name,
			    strerror(errno));
			conn->aborted = true;
			return;
		}

		resid -= actual;
		curptr += actual;
		if (resid == 0) {
			return;
		}

		/* Wait for the connection to accept writes again. */
		if (! conn_io_wait(conn, false)) {
			/* Error already logged. */
			return;
		}
	}
}

/*
 * conn_send_byte --
 *	Convenience wrapper around conn_send() that handles
 *	sending just a single byte.
 */
void
conn_send_byte(struct nabu_connection *conn, uint8_t val)
{
	return conn_send(conn, &val, 1);
}

/*
 * conn_recv --
 *	Receive data on the connection.  Will wait indefinitely for
 *	all data to be received unless the connection watchdog is
 *	enabled.
 */
ssize_t
conn_recv(struct nabu_connection *conn, uint8_t *buf, size_t len)
{
	uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		actual = read(conn->fd, curptr, resid);
		if (actual < 0) {
			log_error("[%s] read() failed: %s", conn->name,
			    strerror(errno));
			conn->aborted = true;
			return;
		}

		resid -= actual;
		curptr += actual;
		if (resid == 0) {
			return;
		}

		/* Wait for the connection to be ready for reads again. */
		if (! conn_io_wait(conn, true)) {
			/* Error already logged. */
			return;
		}
	}
}

/*
 * conn_start_watchdog --
 *	Enable the watchdog timer on this connection.
 */
void
conn_start_watchdog(struct nabu_connection *conn, unsigned int timo_sec)
{
	conn->watchdog = timo_sec;
}

/*
 * conn_stop_watchdog --
 *	Disable the watchdog timer on this connection.
 */
void
conn_stop_watchdog(struct nabu_connection *conn)
{
	conn->watchdog = 0;
}
