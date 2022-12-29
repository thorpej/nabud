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
 * nabud -- a server for the NABU PC.
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
#include "image.h"
#include "log.h"
#include "mj.h"

#define	DEFAULT_NABUD_CONF		"./nabud.conf"

#define	VALID_ATOM(a, t)	((a) != NULL && (a)->type == (t))

static void
config_load_channel(struct image_source *imgsrc, mj_t *atom,
    unsigned int number)
{
	mj_t *name_atom, *type_atom;
	char *name = NULL, *type = NULL;
	image_channel_type ictype;

	if (! VALID_ATOM(atom, MJ_OBJECT)) {
		log_error("Invalid Chanel %u in Source %s.", number,
		    imgsrc->name);
		goto out;
	}
	name_atom = mj_get_atom(atom, "Name");
	if (! VALID_ATOM(name_atom, MJ_STRING)) {
		log_error("Invalid or missing Name for Channel %u "
		    "in Source %s.", number, imgsrc->name);
		goto out;
	}
	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		log_error("Invalid or missing Type for Channel %u "
		    "in Source %s.", number, imgsrc->name);
		goto out;
	}

	mj_asprint(&type, type_atom, MJ_HUMAN);
	if (strcasecmp(type, "pak") == 0) {
		ictype = IMAGE_CHANNEL_PAK;
	} else if (strcasecmp(type, "nabu") == 0) {
		ictype = IMAGE_CHANNEL_NABU;
	} else {
		ictype = IMAGE_CHANNEL_INVALID;
	}

	mj_asprint(&name, name_atom, MJ_HUMAN);

	switch (ictype) {
	case IMAGE_CHANNEL_PAK:
	case IMAGE_CHANNEL_NABU:
		image_source_add_channel(imgsrc, name, ictype, number);
		/* channel now owns these. */
		name = NULL;
		break;

	default:
		log_error("Invalid Type '%s' for Channel %u in Source %s.",
		    type, number, imgsrc->name);
		goto out;
	}

 out:
	if (name != NULL) {
		free(name);
	}
	if (type != NULL) {
		free(type);
	}
}

static void
config_load_source(mj_t *atom, int number)
{
	mj_t *name_atom, *path_atom, *type_atom, *channels_atom;
	char *name = NULL, *path = NULL, *type = NULL;
	image_source_type istype;
	struct image_source *imgsrc;
	int i;

	if (! VALID_ATOM(atom, MJ_OBJECT)) {
		log_error("Invalid Source %d.", number);
		goto out;
	}
	name_atom = mj_get_atom(atom, "Name");
	if (! VALID_ATOM(name_atom, MJ_STRING)) {
		log_error("Invalid or missing Name for Source %d.", number);
		goto out;
	}
	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		log_error("Invalid or missing Type for Source %d.", number);
		goto out;
	}
	channels_atom = mj_get_atom(atom, "Channels");
	if (! VALID_ATOM(channels_atom, MJ_ARRAY)) {
		log_error("Invalid or missing Channels for Source %d.", number);
		goto out;
	}
	if (mj_arraycount(channels_atom) < 1) {
		log_error("No channels in Channels stanza for Source %d.",
		    number);
		goto out;
	}

	mj_asprint(&type, type_atom, MJ_HUMAN);
	if (strcasecmp(type, "local") == 0) {
		istype = IMAGE_SOURCE_LOCAL;
	} else {
		istype = IMAGE_SOURCE_INVALID;
	}

	mj_asprint(&name, name_atom, MJ_HUMAN);

	switch (istype) {
	case IMAGE_SOURCE_LOCAL:
		path_atom = mj_get_atom(atom, "Path");
		if (! VALID_ATOM(path_atom, MJ_STRING)) {
			log_error("Invalid or missing Path for Source %d.",
			    number);
			goto out;
		}
		mj_asprint(&path, path_atom, MJ_HUMAN);
		imgsrc = image_add_local_source(name, path);
		if (imgsrc == NULL) {
			/* Error already logged. */
			goto out;
		}
		/* imgsrc now owns these. */
		name = path = NULL;
		break;

	default:
		log_error("Invalid Type '%s' for Source %d.", type, number);
		goto out;
	}

	for (i = 0; i < mj_arraycount(channels_atom); i++) {
		config_load_channel(imgsrc, mj_get_atom(channels_atom, i),
		    i + 1);
	}

 out:
	if (type != NULL) {
		free(type);
	}
	if (name != NULL) {
		free(name);
	}
	if (path != NULL) {
		free(path);
	}
}

static bool
config_load(const char *path)
{
	mj_t root_atom, *sources_atom /*, *adaptors_atom*/;
	int from, to, tok, i;
	uint8_t *file_data;
	size_t file_size;
	bool ret = false;

	file_data = image_load_file(path, &file_size, 1);
	if (file_data == NULL) {
		log_error("Unable to load configuration file.");
		return false;
	}

	/*
	 * NUL-terminate. file_size is the real size, and we allocated
	 * 1 extra byte.
	 */
	file_data[file_size] = '\0';

	memset(&root_atom, 0, sizeof(root_atom));
	from = to = tok = 0;
	mj_parse(&root_atom, (char *)file_data, &from, &to, &tok);
	free(file_data);

	/* Find the Sources array. */
	sources_atom = mj_get_atom(&root_atom, "Sources");
	if (!VALID_ATOM(sources_atom, MJ_ARRAY)) {
		log_error("Missing or invalid Sources stanza.");
		goto out;
	}
	if (mj_arraycount(sources_atom) < 1) {
		log_error("No sources in Sources stanza.");
		goto out;
	}
	for (i = 0; i < mj_arraycount(sources_atom); i++) {
		config_load_source(mj_get_atom(sources_atom, i), i);
	}

 out:
	mj_delete(&root_atom);
	return ret;
}

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "usage: %s [-c conf] [-d]\n", getprogname());
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

	/*
	 * If the connection was cancelled, go ahead and destroy it
	 * now.
	 */
	if (conn->cancelled) {
		conn_destroy(conn);
	}

	return NULL;
}

int
main(int argc, char *argv[])
{
	const char *nabud_conf = DEFAULT_NABUD_CONF;
	int ch;

	setprogname(argv[0]);

	while ((ch = getopt(argc, argv, "c:d")) != -1) {
		switch (ch) {
		case 'c':
			nabud_conf = DEFAULT_NABUD_CONF;
			break;

		case 'd':
			debug = true;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	/* Set up our signal state. */
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGPIPE, SIG_IGN);

	/* Load our configuration */
	config_load(nabud_conf);

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

	log_info("Received signal %d, shutting down...", sig);
	conn_shutdown();

	exit(0);
}
