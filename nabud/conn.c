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
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "adaptor.h"
#include "conn.h"
#include "image.h"
#include "log.h"
#include "retronet.h"

/* Huh, some platforms don't define INFTIM. */
#ifndef INFTIM
#define	INFTIM		-1
#endif

static pthread_mutex_t conn_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conn_list_cv = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(, nabu_connection) conn_list;
unsigned int conn_count;

static void
conn_insert(struct nabu_connection *conn)
{
	assert(! conn->on_list);

	pthread_mutex_lock(&conn_list_mutex);
	LIST_INSERT_HEAD(&conn_list, conn, link);
	conn->on_list = true;
	conn_count++;
	pthread_cond_signal(&conn_list_cv);
	pthread_mutex_unlock(&conn_list_mutex);
}

static void
conn_remove(struct nabu_connection *conn)
{
	if (conn->on_list) {
		pthread_mutex_lock(&conn_list_mutex);
		LIST_REMOVE(conn, link);
		conn->on_list = false;
		conn_count--;
		pthread_cond_signal(&conn_list_cv);
		pthread_mutex_unlock(&conn_list_mutex);
	}
}

/*
 * conn_shutdown --
 *	Cancel down all active connections.
 */
void
conn_shutdown(void)
{
	struct nabu_connection *conn, *nconn;

	pthread_mutex_lock(&conn_list_mutex);
	LIST_FOREACH_SAFE(conn, &conn_list, link, nconn) {
		conn_cancel(conn);
	}
	while (conn_count) {
		pthread_cond_wait(&conn_list_cv, &conn_list_mutex);
	}
	pthread_mutex_unlock(&conn_list_mutex);
}

/*
 * conn_set_nbio --
 *	Set non-blocking I/O on the specified file descriptor.
 */
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

/*
 * conn_thread --
 *	Worker thread that handles NABU connections.
 */
static void *
conn_thread(void *arg)
{
	struct nabu_connection *conn = arg;

	/* Just run the Adaptor event loop until it returns. */
	adaptor_event_loop(conn);

	/*
	 * If we got there, the connection was cancelled or aborted,
	 * so so ahead and destroy it now.
	 */
	conn_destroy(conn);

	return NULL;
}

/*
 * conn_create_common --
 *	Common connection-creation duties.
 */
static void
conn_create_common(char *name, int fd, unsigned int channel,
    void *(*func)(void *))
{
	struct nabu_connection *conn;
	pthread_attr_t attr;
	int error;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		log_error("[%s] Unable to allocate connection structure.",
		    name);
		close(fd);
		return;
	}
	conn->fd = fd;
	conn->cancel_fds[0] = conn->cancel_fds[1] = -1;

	pthread_mutex_init(&conn->mutex, NULL);

	assert(name != NULL);
	conn->name = name;

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

	/*
	 * If a channel was specified, set it now.
	 */
	if (channel != 0) {
		image_channel_select(conn, (int16_t)channel);
	}

	/*
	 * Create the thread that handles the connection.
	 */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	error = pthread_create(&conn->thread, &attr, func, conn);
	if (error) {
		log_error("pthread_create() for %s failed: %s",
		    name, strerror(error));
		abort();
		/* NOTREACHED */
	}

	conn_insert(conn);
	return;

 bad:
	conn_destroy(conn);
	return;
}

#define	NABU_NATIVE_BPS		111000
#define	NABU_FALLBACK_BPS	115200

/*
 * conn_add_serial --
 *	Add a serial connection.
 */
void
conn_add_serial(char *path, unsigned int channel)
{
	struct termios t;
	int fd;

	log_info("Creating Serial connection on %s.", path);

	fd = open(path, O_RDWR | O_NONBLOCK | O_NOCTTY);
	if (fd < 0) {
		log_error("Unable to open %s: %s", path, strerror(errno));
		return;
	}

	if (tcgetattr(fd, &t) < 0) {
		log_error("tcgetattr() failed on %s: %s", path,
		    strerror(errno));
		goto bad;
	}

	/*
	 * The native protocol is 8N1 @ 111000 baud, but it's much
	 * more reliable if we use 2 stop bits.  Otherwise, the NABU
	 * can get out of sync when receiving a stream of bytes in
	 * a packet.
	 */
	cfmakeraw(&t);
	t.c_cflag &= ~(CSIZE | PARENB | PARODD);
	t.c_cflag |= CLOCAL | CS8 | CSTOPB;
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
		log_info("Failed to 8N2-%d on %s; falling back to 8N2-%d.",
		    NABU_NATIVE_BPS, path, NABU_FALLBACK_BPS);
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

	conn_create_common(path, fd, channel, conn_thread);
 	return;
 bad:
	close(fd);
}

static bool	conn_io_wait(struct nabu_connection *conn,
		    const struct timespec *deadline, bool is_recv);

/*
 * conn_tcp_thread --
 *	Worker thread that handles accepting TCP connections from
 *	NABU emulators (like MAME).
 */
static void *
conn_tcp_thread(void *arg)
{
	struct nabu_connection *conn = arg;
	struct image_channel *chan;
	char host[NI_MAXHOST];
	struct sockaddr_storage peerss;
	socklen_t peersslen;
	int sock, v;

	/* Never a deadline for these. */
	struct timespec deadline = { 0, 0 };

	for (;;) {
		if (! conn_io_wait(conn, &deadline, true)) {
			if (conn->state == CONN_STATE_CANCELLED) {
				log_info("[%s] Received cancellation request.",
				    conn->name);
				break;
			}
			break;
		}
		peersslen = sizeof(peerss);
		sock = accept(conn->fd, (struct sockaddr *)&peerss, &peersslen);
		if (sock < 0) {
			if (errno != EAGAIN) {
				log_error("[%s] accept() failed: %s",
				    conn->name, strerror(errno));
				conn->state = CONN_STATE_ABORTED;
				break;
			}
			continue;
		}

		/* Disable Nagle. */
		v = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v));

		/* Get the numeric peer name string. */
		v = getnameinfo((struct sockaddr *)&peerss,
		    peersslen, host, sizeof(host), NULL, 0,
		    NI_NUMERICHOST);
		if (v) {
			log_error("[%s] getnameinfo() failed: %s",
			    conn->name, gai_strerror(v));
			close(sock);
			continue;
		}

		log_info("[%s] Creating TCP connection for %s.",
		    conn->name, host);

		pthread_mutex_lock(&conn->mutex);
		chan = conn->l_channel;
		pthread_mutex_unlock(&conn->mutex);

		conn_create_common(strdup(host), sock,
		    chan != NULL ? chan->number : 0, conn_thread);
	}

	/* Error on the listen socket -- He's dead, Jim. */
	conn_destroy(conn);

	return NULL;
}

/*
 * conn_add_tcp --
 *	Add a TCP listener.  This creates a "connection" that simply
 *	listens for incoming connections from the network and in-turn
 *	creates new connections to service them.
 */
void
conn_add_tcp(char *portstr, unsigned int channel)
{
	int sock;
	long port;
	char name[sizeof("IPv4-65536")];

	log_info("Creating TCP listener on port %s.", portstr);

	port = strtol(portstr, NULL, 10);
	if (port < 1 || port > UINT16_MAX) {
		log_error("Invalid TCP port number: %s", portstr);
		return;
	}

	struct sockaddr_in sin = {
		.sin_len = sizeof(sin),
		.sin_family = AF_INET,
		.sin_port = htons((in_port_t)port),
		.sin_addr = { .s_addr = htonl(INADDR_ANY) },
	};

	snprintf(name, sizeof(name), "IPv4-%ld", port);
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock >= 0) {
		if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
			if (listen(sock, 8) == 0) {
				conn_create_common(strdup(name), sock, channel,
				    conn_tcp_thread);
				sock = -1;
			} else {
				log_error("Unable to listen on IPv4 socket: %s",
				    strerror(errno));
			}
		} else {
			log_error("Unable to bind IPv4 socket: %s",
			    strerror(errno));
		}
	} else {
		log_error("Unable to create IPv4 socket: %s",
		    strerror(errno));
	}
	if (sock >= 0) {
		close(sock);
	}

#ifdef PF_INET6
	struct sockaddr_in6 sin6 = {
		.sin6_len = sizeof(sin6),
		.sin6_family = AF_INET6,
		.sin6_port = htons((in_port_t)port),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};

	snprintf(name, sizeof(name), "IPv6-%ld", port);
	sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock >= 0) {
		if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) == 0) {
			if (listen(sock, 8) == 0) {
				conn_create_common(strdup(name), sock, channel,
				    conn_tcp_thread);
				sock = -1;
			} else {
				log_error("Unable to listen on IPv6 socket: %s",
				    strerror(errno));
			}
		} else {
			log_error("Unable to bind IPv6 socket: %s",
			    strerror(errno));
		}
	} else {
		log_error("Unable to create IPv6 socket: %s",
		    strerror(errno));
	}
	if (sock >= 0) {
		close(sock);
	}
#endif /* PF_INET6 */
}

/*
 * conn_destroy --
 *	Destroy a connection structure.
 */
void
conn_destroy(struct nabu_connection *conn)
{
	conn_remove(conn);

	image_release(conn_set_last_image(conn, NULL));
	rn_store_clear(conn);

	pthread_mutex_destroy(&conn->mutex);

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
 * conn_get_last_image --
 *	Return the last image used by the connection.
 */
struct nabu_image *
conn_get_last_image(struct nabu_connection *conn)
{
	struct nabu_image *img;

	pthread_mutex_lock(&conn->mutex);
	img = conn->l_last_image;
	pthread_mutex_unlock(&conn->mutex);

	return img;
}

/*
 * conn_set_last_image --
 *	Set the specified image as the most-recent.  Returns
 *	the old value.
 */
struct nabu_image *
conn_set_last_image(struct nabu_connection *conn, struct nabu_image *img)
{
	struct nabu_image *oimg;

	pthread_mutex_lock(&conn->mutex);
	oimg = conn->l_last_image;
	conn->l_last_image = img;
	pthread_mutex_unlock(&conn->mutex);

	return oimg;
}

/*
 * conn_set_last_image_if --
 *	Like conn_set_last_image(), but only if the last image
 *	matches the specified match value.
 */
struct nabu_image *
conn_set_last_image_if(struct nabu_connection *conn, struct nabu_image *match,
    struct nabu_image *img)
{
	struct nabu_image *oimg;

	pthread_mutex_lock(&conn->mutex);
	if (conn->l_last_image == match) {
		oimg = conn->l_last_image;
		conn->l_last_image = img;
	} else {
		oimg = NULL;
	}
	pthread_mutex_unlock(&conn->mutex);

	return oimg;
}

/*
 * conn_get_channel --
 *	Return the connection's currently-selected channel.
 */
struct image_channel *
conn_get_channel(struct nabu_connection *conn)
{
	struct image_channel *chan;

	pthread_mutex_lock(&conn->mutex);
	chan = conn->l_channel;
	pthread_mutex_unlock(&conn->mutex);

	return chan;
}

/*
 * conn_set_channel --
 *	Set the specified channel as the connection's selected channel.
 */
void
conn_set_channel(struct nabu_connection *conn, struct image_channel *chan)
{
	pthread_mutex_lock(&conn->mutex);
	conn->l_channel = chan;
	pthread_mutex_unlock(&conn->mutex);
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
	conn->state = CONN_STATE_CANCELLED;
	(void) write(conn->cancel_fds[1], &conn->state, sizeof(conn->state));
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
conn_io_polltimo(struct nabu_connection *conn, const struct timespec *deadline,
    bool is_recv)
{
	struct timespec now, timo;
	const char *which = is_recv ? "recv" : "send";

	if (deadline->tv_sec == 0 && deadline->tv_nsec == 0) {
		log_debug("[%s] No %s deadline, returning INFTIM.",
		    conn->name, which);
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
		log_debug("[%s] Deadline for %s has passed, returning 0 ms.",
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
	log_debug("[%s] next %s timeout: %d ms", conn->name, which,
	    (int)millis);
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
		log_info("[%s] Connection (%s) timed out.", conn->name,
		    which);
		conn->state = CONN_STATE_ABORTED;
		return false;
	}
	if (fds[1].revents) {
		if (fds[1].revents & POLLIN) {
			log_debug("[%s] Connection cancelled.",
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
	conn->state = CONN_STATE_ABORTED;
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
 * conn_recv_byte --
 *	Convenience wrapper around conn_recv() that handles
 *	receiving just a single byte.
 */
bool
conn_recv_byte(struct nabu_connection *conn, uint8_t *val)
{
	return conn_recv(conn, val, 1);
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
