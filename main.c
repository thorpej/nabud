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
 * NaturalAccess -- a server for the NABU PC.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "adaptor.h"
#include "conn.h"
#include "log.h"
#include "segment.h"

#ifndef DEFAULT_NABU_SEGMENTS_DIR
#define	DEFAULT_NABU_SEGMENTS_DIR	"./nabu_segments"
#endif

static int	debug = true;

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "usage: %s [-d] [-s segments_dir] [tty_path [...]]\n",
	    getprogname());
	exit(EXIT_FAILURE);
}

static void *
connection_thread(void *arg)
{
	struct nabu_connection *conn = arg;

	/*
	 * Just run the Adaptor event loop until it returns.
	 */
	adaptor_event_loop(conn);
	return NULL;
}

int
main(int argc, char *argv[])
{
	const char *segdir = DEFAULT_NABU_SEGMENTS_DIR;
	int ch;

	setprogname(argv[0]);

	while ((ch = getopt(argc, argv, "ds:")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;

		case 's':
			segdir = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (! segment_init(segdir)) {
		/* Error already logged. */
		exit(EXIT_FAILURE);
	}

	/* Set up our signal state. */
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGPIPE, SIG_IGN);

	/*
	 * For each tty_path, create a serial connection and create a
	 * thread to service it.
	 */
	struct nabu_connection *conn;
	pthread_t thread;
	pthread_attr_t attr;
	int error;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	for (; argc != 0; argc--, argv++) {
		log_info("Creating serial connection on %s.", *argv);
		conn = conn_create_serial(*argv);
		if (conn == NULL) {
			/* Not fatal.  Error already logged. */
			continue;
		}
		error = pthread_create(&thread, &attr, connection_thread, conn);
		if (error) {
			log_error("pthread_create() for %s failed: %s",
			    *argv, strerror(error));
			abort();
			/* NOTREACHED */
		}
	}

	if (conn_count == 0) {
		log_error("No connections! So boring! Goodbye.");
		exit(EXIT_FAILURE);
	}

	/*
	 * Now that our connections are up and running, just wait
	 * for a clean-shutdown signal.
	 */
	sigset_t waitset;
	int sig;

	sigemptyset(&waitset);
	sigaddset(&waitset, SIGINT);
	sigaddset(&waitset, SIGTERM);

	if (sigwait(&waitset, &sig) != 0) {
		log_fatal("sigwait() failed: %s\n", strerror(errno));
		/* NOTREACHED */
	}

	log_info("Exiting on signal %d.", sig);
	/* XXX Shut down all connections. */
	exit(0);
}
