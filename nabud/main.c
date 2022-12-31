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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#ifndef NABUD_CONF
#define	NABUD_CONF		"/etc/nabud.conf"
#endif

#define	VALID_ATOM(a, t)	((a) != NULL && (a)->type == (t))

static bool	foreground;

static void
config_error(const char *preamble, mj_t *atom)
{
	char *atom_str;

	mj_asprint(&atom_str, atom, MJ_HUMAN);
	log_error("%s:\n%s", preamble, atom_str);
	free(atom_str);
}

static void
config_load_channel(mj_t *atom)
{
	mj_t *name_atom, *number_atom, *type_atom, *source_atom;
	char *name = NULL, *number = NULL, *type = NULL, *source = NULL;
	image_channel_type ictype;
	long val;

	if (! VALID_ATOM(atom, MJ_OBJECT)) {
		config_error("Invalid Channel object", atom);
		goto out;
	}

	name_atom = mj_get_atom(atom, "Name");
	if (! VALID_ATOM(name_atom, MJ_STRING)) {
		config_error("Invalid or missing Name in Channel object",
		    atom);
		goto out;
	}
	mj_asprint(&name, name_atom, MJ_HUMAN);

	number_atom = mj_get_atom(atom, "Number");
	if (! VALID_ATOM(number_atom, MJ_NUMBER)) {
		config_error("Invalid or missing Number in Channel object",
		    atom);
		goto out;
	}
	mj_asprint(&number, number_atom, MJ_HUMAN);
	val = strtol(number, NULL, 10);
	if (val < 1 || val > 255) {
		config_error("Channel Number must be between 1 and 255",
		    atom);
		goto out;
	}

	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		config_error("Invalid or missing Type in Channel object",
		    atom);
		goto out;
	}
	mj_asprint(&type, type_atom, MJ_HUMAN);
	if (strcasecmp(type, "pak") == 0) {
		ictype = IMAGE_CHANNEL_PAK;
	} else if (strcasecmp(type, "nabu") == 0) {
		ictype = IMAGE_CHANNEL_NABU;
	} else {
		config_error("Channel Type must be pak or nabu", atom);
		goto out;
	}

	source_atom = mj_get_atom(atom, "Source");
	if (! VALID_ATOM(source_atom, MJ_STRING)) {
		config_error("Invalid or missing Source in Channel object",
		    atom);
	}
	mj_asprint(&source, source_atom, MJ_HUMAN);

	image_add_channel(ictype, name, source, val);
	/* image_add_channel() owns these */
	name = source = NULL;

 out:
	if (name != NULL) {
		free(name);
	}
	if (number != NULL) {
		free(number);
	}
	if (type != NULL) {
		free(type);
	}
	if (source != NULL) {
		free(source);
	}
}

static void
config_load_source(mj_t *atom)
{
	mj_t *name_atom, *loc_atom, *type_atom;
	char *name = NULL, *loc = NULL, *type = NULL;

	if (! VALID_ATOM(atom, MJ_OBJECT)) {
		config_error("Invalid Source object", atom);
		goto out;
	}

	name_atom = mj_get_atom(atom, "Name");
	if (! VALID_ATOM(name_atom, MJ_STRING)) {
		config_error("Invalid or missing Name in Source object",
		    atom);
		goto out;
	}
	mj_asprint(&name, name_atom, MJ_HUMAN);

	loc_atom = mj_get_atom(atom, "Location");
	if (! VALID_ATOM(loc_atom, MJ_STRING)) {
		config_error("Invalid or missing Location in Source object",
		    atom);
		goto out;
	}
	mj_asprint(&loc, loc_atom, MJ_HUMAN);

	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		config_error("Invalid or missing Type in Source object",
		    atom);
		goto out;
	}
	mj_asprint(&type, type_atom, MJ_HUMAN);

	if (strcasecmp(type, "local") == 0) {
		image_add_local_source(name, loc);
		/* image_add_local_source() owns these. */
		name = loc = NULL;
	} else {
		config_error("Source Type must be Local", atom);
		goto out;
	}

 out:
	if (name != NULL) {
		free(name);
	}
	if (loc != NULL) {
		free(loc);
	}
	if (type != NULL) {
		free(type);
	}
}

static void
config_load_connection(mj_t *atom)
{
	mj_t *type_atom, *port_atom, *channel_atom;
	char *type = NULL, *port = NULL, *channel = NULL;
	long val;

	if (! VALID_ATOM(atom, MJ_OBJECT)) {
		config_error("Invalid Connection object.", atom);
		goto out;
	}

	port_atom = mj_get_atom(atom, "Port");
	if (! VALID_ATOM(port_atom, MJ_STRING)) {
		config_error("Invalid or missing Port in Connection object",
		    atom);
		goto out;
	}
	mj_asprint(&port, port_atom, MJ_HUMAN);

	/* Channel is optional. */
	channel_atom = mj_get_atom(atom, "Channel");
	if (VALID_ATOM(channel_atom, MJ_NUMBER)) {
		mj_asprint(&channel, channel_atom, MJ_HUMAN);
		val = strtol(channel, NULL, 10);
		if (val < 1 || val > 255) {
			config_error("Channel must be between 1 and 255",
			    atom);
			goto out;
		}
	} else {
		val = 0;
	}

	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		config_error("Invalid or missing Type in Connection object",
		    atom);
		goto out;
	}
	mj_asprint(&type, type_atom, MJ_HUMAN);

	if (strcasecmp(type, "serial") == 0) {
		conn_add_serial(port, val);
		/* conn_add_serial() owns these. */
		port = NULL;
	} else if (strcasecmp(type, "tcp") == 0) {
		conn_add_tcp(port, val);
		/* conn_add_tcp() owns these. */
		port = NULL;
	} else {
		config_error("Connection Type must be Serial or TCP", atom);
		goto out;
	}

 out:
	if (type != NULL) {
		free(type);
	}
	if (port != NULL) {
		free(port);
	}
	if (channel != NULL) {
		free(channel);
	}
}

static bool
config_load(const char *path)
{
	mj_t root_atom, *sources_atom, *channels_atom, *connections_atom;
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

	/* Find the Channels array. */
	channels_atom = mj_get_atom(&root_atom, "Channels");
	if (!VALID_ATOM(channels_atom, MJ_ARRAY)) {
		log_error("Missing or invalid Channels stanza.");
		goto out;
	}

	/* Find the Connections array. */
	connections_atom = mj_get_atom(&root_atom, "Connections");
	if (!VALID_ATOM(connections_atom, MJ_ARRAY)) {
		log_error("Missing or invalid Connections stanza.");
		goto out;
	}

	/* Load up the sources. */
	for (i = 0; i < mj_arraycount(sources_atom); i++) {
		config_load_source(mj_get_atom(sources_atom, i));
	}

	/* Load up the channels. */
	for (i = 0; i < mj_arraycount(channels_atom); i++) {
		config_load_channel(mj_get_atom(channels_atom, i));
	}

	/* Load up the connections. */
	for (i = 0; i < mj_arraycount(connections_atom); i++) {
		config_load_connection(mj_get_atom(connections_atom, i));
	}

 out:
	mj_delete(&root_atom);
	return ret;
}

static const char nabud_version[] = VERSION;

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "%s version %s\n", getprogname(), nabud_version);
	fprintf(stderr, "usage: %s [-c conf] [-d] [-f] [-l logfile]\n",
	    getprogname());
	fprintf(stderr, "       -c conf    specifies the configuration file\n");
	fprintf(stderr, "       -d         enable debugging (implies -f)\n");
	fprintf(stderr, "       -f         run in the foreground\n");
	fprintf(stderr, "       -l logfile specifies the log file\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	const char *nabud_conf = NABUD_CONF;
	unsigned int logopts = 0;
	const char *logfile = NULL;
	int ch;

	setprogname(argv[0]);

	while ((ch = getopt(argc, argv, "c:dfl:")) != -1) {
		switch (ch) {
		case 'c':
			nabud_conf = optarg;
			break;

		case 'd':
			/* debug implies foreground */
			logopts |= LOG_OPT_DEBUG;
			/* FALLTHROUGH */

		case 'f':
			logopts |= LOG_OPT_FOREGROUND;
			foreground = true;
			break;

		case 'l':
			logfile = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage();
		/* NOTREACHED */
	}

	/* Initlalize logging. */
	if (! log_init(logfile, logopts)) {
		/* Error message already displayed. */
		exit(EXIT_FAILURE);
	}

	/* If we're not running in the foreground, daemonize ourselves now. */
	if (!foreground && daemon(0, 0) < 0) {
		fprintf(stderr, "Unable to daemonize: %s\n",
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Set up our signal state. */
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGPIPE, SIG_IGN);

	log_info("Welcome to NABU! I'm version %s of your host, %s.",
	    nabud_version, getprogname());

	/* Load our configuration */
	config_load(nabud_conf);

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
	log_info("Exiting. Thank you, come again!");
	log_fini();

	exit(0);
}
