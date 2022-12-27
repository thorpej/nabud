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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "conn.h"
#include "log.h"

static pthread_mutex_t conn_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conn_list_cv = PTHREAD_COND_INITIALIZER;
static struct nabu_connection *conn_list;
unsigned int conn_count;

static void
conn_insert(struct nabu_connection *conn)
{
	assert(! conn->on_list);

	pthread_mutex_lock(&conn_list_mutex);
	conn->next = conn_list;
	conn_list = conn;
	conn->on_list = true;
	conn_count++;
	pthread_cond_signal(&conn_list_cv);
	pthread_mutex_unlock(&conn_list_mutex);
}

static void
conn_remove(struct nabu_connection *conn)
{
	if (conn->on_list) {
		struct nabu_connection *cur, **prev_nextp;

		pthread_mutex_lock(&conn_list_mutex);
		for (cur = conn_list, prev_nextp = &conn_list;
		     cur != NULL;
		     prev_nextp = &cur->next, cur = cur->next) {
			if (cur == conn) {
				*prev_nextp = cur->next;
				cur->next = NULL;
				conn->on_list = false;
				conn_count--;
				pthread_cond_signal(&conn_list_cv);
				break;
			}
		}
		pthread_mutex_unlock(&conn_list_mutex);
		assert(cur != NULL);
	}
}

/*
 * conn_shutdown --
 *	Cancel down all active connections.
 */
void
conn_shutdown(void)
{
	struct nabu_connection *conn;

	pthread_mutex_lock(&conn_list_mutex);
	for (conn = conn_list; conn != NULL; conn = conn->next) {
		conn_cancel(conn);
	}
	while (conn_count) {
		pthread_cond_wait(&conn_list_cv, &conn_list_mutex);
	}
	pthread_mutex_unlock(&conn_list_mutex);
}

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

static struct nabu_connection *
conn_create_common(const char *name, int fd)
{
	struct nabu_connection *conn;

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
		log_error("[%s] pipe() failed: %s", name, strerror(errno));
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

	conn_insert(conn);
	return conn;

 bad:
	conn_destroy(conn);
	return NULL;
}

#define	NABU_NATIVE_BPS		111000
#define	NABU_FALLBACK_BPS	115200

struct nabu_connection *
conn_create_serial(const char *path)
{
	struct termios t;
	int fd;

	fd = open(path, O_RDWR | O_NONBLOCK | O_NOCTTY);
	if (fd < 0) {
		log_error("Unable to open %s: %s", path, strerror(errno));
		return NULL;
	}

	if (tcgetattr(fd, &t) < 0) {
		log_error("tcgetattr() failed on %s: %s", path,
		    strerror(errno));
		goto bad;
	}

	/* 8N1, 111000 baud natively. */
	cfmakeraw(&t);
	t.c_cflag &= ~(CSIZE | CSTOPB | PARENB | PARODD);
	t.c_cflag |= CLOCAL | CS8;
	if (cfsetspeed(&t, NABU_NATIVE_BPS) < 0) {
		log_error("cfsetspeed(NABU_NATIVE_BPS) on %s failed.",
		    path);
		goto bad;
	}

	if (tcsetattr(fd, TCSANOW, &t) < 0) {
		/*
		 * If we failed to set the native NABU baud rate
		 * (it's a little of an odd-ball after all), then
		 * try the fall back.  But add an extra stop bit
		 * so that the NABU's UART has a better chance of
		 * re-synchronizing with the next start bit.
		 */
		log_info("Failed to 8N1-%d on %s; falling back to 8N2-%d.",
		    NABU_NATIVE_BPS, path, NABU_FALLBACK_BPS);
		t.c_cflag |= CSTOPB;
		if (cfsetspeed(&t, NABU_FALLBACK_BPS)) {
			log_error("cfsetspeed(NABU_FALLBACK_BPS) on %s failed.",
			    path);
			goto bad;
		}
		if (tcsetattr(fd, TCSANOW, &t) < 0) {
			log_error("Failed to set 8N2-%d on %s.",
			    NABU_FALLBACK_BPS, path);
			goto bad;
		}
	}

	return conn_create_common(path, fd);
 bad:
	close(fd);
	return NULL;
}

/*
 * conn_destroy --
 *	Destroy a connection structure.
 */
void
conn_destroy(struct nabu_connection *conn)
{
	conn_remove(conn);

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
conn_io_polltimo(struct nabu_connection *conn, const struct timespec *deadline)
{
	struct timespec now, timo;

	if (deadline->tv_sec == 0 && deadline->tv_nsec == 0) {
		log_debug("[%s] No deadline, returning INFTIM.", conn->name);
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
		log_debug("[%s] Deadline has passed, returning 0 ms.",
		    conn->name);
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
	log_debug("[%s] next timeout: %d ms", conn->name, (int)millis);
	return (int)millis;
}

/*
 * conn_io_wait --
 *	Wait to be able to do I/O on a connection.
 */
static bool
conn_io_wait(struct nabu_connection *conn, const struct timespec *deadline,
    bool is_recv)
{
	short pollwhich = is_recv ? POLLRDNORM : POLLWRNORM;
	struct pollfd fds[2] = {
		[0] = {
			.fd = conn->fd,
			.events = pollwhich | POLLERR | POLLHUP | POLLNVAL,
		},
		[1] = {
			.fd = conn->cancel_fds[0],
			.events = POLLRDNORM | POLLERR | POLLHUP | POLLNVAL,
		},
	};
	int pollret;
	const char *which = is_recv ? "recv" : "send";

	pollret = poll(fds, 2, conn_io_polltimo(conn, deadline));
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
	log_error("[%s] Connection failure in %s: fds[0].revents = 0x%04x.",
	    conn->name, which, fds[0].revents);
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
	struct timespec deadline;
	const uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		actual = write(conn->fd, curptr, resid);
		if (actual < 0 && errno != EAGAIN) {
			log_error("[%s] write() failed: %s", conn->name,
			    strerror(errno));
			conn->aborted = true;
			return;
		}

		if (actual > 0) {
			resid -= actual;
			curptr += actual;
			if (resid == 0) {
				return;
			}
		}

		/* Wait for the connection to accept writes again. */
		if (! conn_io_wait(conn, &deadline, false)) {
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
 *
 *	N.B. We wait for ALL of the expected data to arrive.  There
 *	are no partial reads!
 */
bool
conn_recv(struct nabu_connection *conn, uint8_t *buf, size_t len)
{
	struct timespec deadline;
	uint8_t *curptr;
	size_t resid;
	ssize_t actual;

	resid = len;
	curptr = buf;

	conn_io_deadline(conn, &deadline);

	for (;;) {
		actual = read(conn->fd, curptr, resid);
		if (actual < 0 && errno != EAGAIN) {
			log_error("[%s] read() failed: %s", conn->name,
			    strerror(errno));
			conn->aborted = true;
			return false;
		}

		if (actual > 0) {
			resid -= actual;
			curptr += actual;
			if (resid == 0) {
				return true;
			}
		}

		/* Wait for the connection to be ready for reads again. */
		if (! conn_io_wait(conn, &deadline, true)) {
			/* Error already logged. */
			return false;
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
