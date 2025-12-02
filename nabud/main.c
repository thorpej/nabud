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

#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libnabud/fileio.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"

#include "adaptor.h"
#include "conn.h"
#include "control.h"
#include "image.h"

#include "../libmj/mj.h"

#ifndef NABUD_CONF
#define	NABUD_CONF		INSTALL_PREFIX "/etc/nabud.conf"
#endif

#define	VALID_ATOM(a, t)	((a) != NULL && (a)->type == (t))

static bool	foreground;
mode_t		nabud_umask;

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
	mj_t *name_atom, *number_atom, *type_atom, *source_atom, *path_atom,
	    *list_url_atom, *default_file_atom, *rn_enabled_atom;
	char *type = NULL, *number = NULL, *path = NULL;
	struct image_add_channel_args args = { };
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
	mj_asprint(&args.name, name_atom, MJ_HUMAN);

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
	args.number = (unsigned int)val;

	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		config_error("Invalid or missing Type in Channel object",
		    atom);
		goto out;
	}
	mj_asprint(&type, type_atom, MJ_HUMAN);
	if (strcasecmp(type, "pak") == 0) {
		args.type = IMAGE_CHANNEL_PAK;
	} else if (strcasecmp(type, "nabu") == 0) {
		args.type = IMAGE_CHANNEL_NABU;
	} else {
		config_error("Channel Type must be pak or nabu", atom);
		goto out;
	}

	source_atom = mj_get_atom(atom, "Source");
	if (! VALID_ATOM(source_atom, MJ_STRING)) {
		config_error("Invalid or missing Source in Channel object",
		    atom);
	}
	mj_asprint(&args.source, source_atom, MJ_HUMAN);

	/*
	 * Optional Path -- specifies a path relative to the
	 * Source root that contains the files for this channel.
	 */
	path_atom = mj_get_atom(atom, "Path");
	if (VALID_ATOM(path_atom, MJ_STRING)) {
		mj_asprint(&path, path_atom, MJ_HUMAN);
		args.relpath = path;
	}

	/*
	 * Optional ListURL -- specifies a file list for the
	 * channel.  This is used by NabuRetroNet.
	 */
	list_url_atom = mj_get_atom(atom, "ListURL");
	if (VALID_ATOM(list_url_atom, MJ_STRING)) {
		mj_asprint(&args.list_url, list_url_atom, MJ_HUMAN);
	}

	/*
	 * Optional DefaultFile -- specifies the default file that
	 * will be vended when the NABU requests image 000001.
	 */
	default_file_atom = mj_get_atom(atom, "DefaultFile");
	if (VALID_ATOM(default_file_atom, MJ_STRING)) {
		mj_asprint(&args.default_file, default_file_atom, MJ_HUMAN);
	}

	/*
	 * Optional RetroNetExtensions -- specifies whether or not
	 * RetroNet extensions are enabled for this channel.
	 */
	rn_enabled_atom = mj_get_atom(atom, "RetroNetExtensions");
	if (VALID_ATOM(rn_enabled_atom, MJ_TRUE)) {
		args.retronet_enabled = true;
	}

	image_add_channel(&args);
	/* image_add_channel() owns these */
	args.name = args.source = args.list_url = args.default_file = NULL;

 out:
	if (args.name != NULL) {
		free(args.name);
	}
	if (number != NULL) {
		free(number);
	}
	if (type != NULL) {
		free(type);
	}
	if (args.source != NULL) {
		free(args.source);
	}
	if (path != NULL) {
		free(path);
	}
	if (args.list_url != NULL) {
		free(args.list_url);
	}
	if (args.default_file != NULL) {
		free(args.default_file);
	}
}

static void
config_load_source(mj_t *atom)
{
	mj_t *name_atom, *loc_atom;
	struct image_add_source_args args = { };

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
	mj_asprint(&args.name, name_atom, MJ_HUMAN);

	loc_atom = mj_get_atom(atom, "Location");
	if (! VALID_ATOM(loc_atom, MJ_STRING)) {
		config_error("Invalid or missing Location in Source object",
		    atom);
		goto out;
	}
	mj_asprint(&args.root, loc_atom, MJ_HUMAN);

	image_add_source(&args);
	/* image_add_source() owns these. */
	args.name = NULL;
	args.root = NULL;

 out:
	if (args.name != NULL) {
		free(args.name);
	}
	if (args.root != NULL) {
		free(args.root);
	}
}

static void
config_load_connection(mj_t *atom)
{
	mj_t *type_atom, *port_atom, *channel_atom, *file_root_atom,
	    *baud_atom, *flow_control_atom, *stop_bits_atom;
	char *type = NULL, *channel = NULL, *baud = NULL, *stop_bits = NULL;
	struct conn_add_args args = { };
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
	mj_asprint(&args.port, port_atom, MJ_HUMAN);

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
	args.channel = (unsigned int)val;

	/*
	 * Baud is optional.  If it's not present, also check for
	 * BaudRate (which is equally optional).
	 */
	baud_atom = mj_get_atom(atom, "Baud");
	if (! VALID_ATOM(baud_atom, MJ_NUMBER)) {
		baud_atom = mj_get_atom(atom, "BaudRate");
	}
	if (VALID_ATOM(baud_atom, MJ_NUMBER)) {
		mj_asprint(&baud, baud_atom, MJ_HUMAN);
		val = strtol(baud, NULL, 10);
		if (val < 1) {
			config_error("Baud must be at least 1", atom);
			goto out;
		}
	} else {
		val = 0;
	}
	args.baud = (unsigned int)val;

	/* FlowControl is optional. */
	flow_control_atom = mj_get_atom(atom, "FlowControl");
	if (VALID_ATOM(flow_control_atom, MJ_TRUE)) {
		args.flow_control = true;
	}

	/*
	 * StopBits is optional.
	 */
	stop_bits_atom = mj_get_atom(atom, "StopBits");
	if (VALID_ATOM(stop_bits_atom, MJ_NUMBER)) {
		mj_asprint(&stop_bits, stop_bits_atom, MJ_HUMAN);
		val = strtol(stop_bits, NULL, 10);
		if (val != 1 && val != 2) {
			config_error("StopBits must be 1 or 2", atom);
			goto out;
		}
	} else {
		val = 0;
	}
	args.stop_bits = (unsigned int)val;

	/*
	 * StorageArea is optional, and we also check for the old
	 * name (FileRoot).
	 */
	file_root_atom = mj_get_atom(atom, "StorageArea");
	if (file_root_atom == NULL) {
		file_root_atom = mj_get_atom(atom, "FileRoot");
	}
	if (VALID_ATOM(file_root_atom, MJ_STRING)) {
		mj_asprint(&args.file_root, file_root_atom, MJ_HUMAN);
	}

	type_atom = mj_get_atom(atom, "Type");
	if (! VALID_ATOM(type_atom, MJ_STRING)) {
		config_error("Invalid or missing Type in Connection object",
		    atom);
		goto out;
	}
	mj_asprint(&type, type_atom, MJ_HUMAN);

	if (strcasecmp(type, "serial") == 0) {
		conn_add_serial(&args);
		/* conn_add_serial() owns these. */
		args.port = args.file_root = NULL;
	} else if (strcasecmp(type, "tcp") == 0) {
		conn_add_tcp(&args);
		/* conn_add_tcp() owns these. */
		args.port = args.file_root = NULL;
	} else {
		config_error("Connection Type must be Serial or TCP", atom);
		goto out;
	}

 out:
	if (type != NULL) {
		free(type);
	}
	if (args.port != NULL) {
		free(args.port);
	}
	if (channel != NULL) {
		free(channel);
	}
	if (baud != NULL) {
		free(baud);
	}
	if (stop_bits != NULL) {
		free(stop_bits);
	}
	if (args.file_root != NULL) {
		free(args.file_root);
	}
}

static bool
config_load(const char *path)
{
	mj_t root_atom, *sources_atom, *channels_atom, *connections_atom;
	int from, to, tok, i;
	uint8_t *file_data = NULL;
	size_t file_size;
	bool ret = false;

	/*
	 * Read in the config file.  Ask for 1 extra byte to be allocated
	 * so we can ensure NUL-termination.
	 */
	file_data = fileio_load_file_from_location(path, FILEIO_O_TEXT,
	    1 /*extra*/, 0 /*maxsize*/, NULL, &file_size);
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

const char nabud_version[] = VERSION;

#define	GETOPT_FLAGS	"c:d:fl:u:U:"

#if defined(__APPLE__)
#define	PLATFORM_GETOPT_FLAGS	"L"
#define	PLATFORM_USAGE_STRING	" [-L]"
#elif defined(__linux__)
#define	PLATFORM_GETOPT_FLAGS	"S"
#define	PLATFORM_USAGE_STRING	" [-S]"
#else
#define	PLATFORM_GETOPT_FLAGS	/* nothing */
#define	PLATFORM_USAGE_STRING	""
#endif

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "%s version %s\n", getprogname(), nabud_version);
	fprintf(stderr, "usage: %s [-c conf] [-d subsys] [-f] [-l logfile] "
			          "[-u user] [-U umask]%s\n",
	    getprogname(), PLATFORM_USAGE_STRING);
	fprintf(stderr, "       -c conf    specifies the configuration file\n");
	fprintf(stderr, "       -d subsys  enable debugging (implies -f)\n");
	fprintf(stderr, "       -f         run in the foreground\n");
	fprintf(stderr, "       -l logfile specifies the log file\n");
#if defined(__APPLE__)
	fprintf(stderr, "       -L         run in launchd mode\n");
#endif
#if defined(__linux__)
	fprintf(stderr, "       -S         run in systemd mode\n");
#endif
	fprintf(stderr, "       -u user    specifies user to run as\n");
	fprintf(stderr, "       -U umask   specifies umask for file creation\n");

	fprintf(stderr, "\nValid subsystems for -d:\n");
	log_subsys_list(stderr, "\t");

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	const char *nabud_conf = NABUD_CONF;
	unsigned int logopts = 0;
	const char *logfile = NULL;
	const char *as_user = NULL;
	const char *with_umask = NULL;
	int ch;

	setprogname(argv[0]);

	while ((ch = getopt(argc, argv,
			    GETOPT_FLAGS PLATFORM_GETOPT_FLAGS)) != -1) {
		switch (ch) {
		case 'c':
			nabud_conf = optarg;
			break;

		case 'd':
			/* debug implies foreground */
			if (! log_debug_enable(optarg)) {
				usage();
			}
			/* FALLTHROUGH */

		case 'f':
			logopts |= LOG_OPT_FOREGROUND;
			foreground = true;
			break;

		case 'l':
			logfile = optarg;
			break;

#if defined(__APPLE__)
		case 'L':
			/* Run in foreground, but with normal logging. */
			foreground = true;
			break;
#endif
#if defined(__linux__)
		case 'S':
			/* Run in foreground, but with normal logging. */
			foreground = true;
			break;
#endif

		case 'u':
			as_user = optarg;
			break;

		case 'U':
			with_umask = optarg;
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

	/*
	 * If we've been asked to run as an unprivileged user, switch
	 * to that user now, before we attempt to create any files.
	 */
	if (as_user != NULL) {
		struct passwd *pwd;

		pwd = getpwnam(as_user);
		if (pwd == NULL) {
			errx(EXIT_FAILURE, "Unknown user: %s", as_user);
		}

		/*
		 * If we're already the specified user, then there's nothing
		 * to do.  Otherwise, if we're not the running as the super-
		 * user, then we can't do what's been requested.
		 */
		if (getuid() != pwd->pw_uid) {
			if (geteuid() != 0) {
				errx(EXIT_FAILURE,
				    "Already running as UID %d; "
				    "cannot switch to user %s", geteuid(),
				    as_user);
			}
			if (setgid(pwd->pw_gid) < 0) {
				err(EXIT_FAILURE, "setgid(%d)", pwd->pw_gid);
			}
			if (initgroups(as_user, pwd->pw_gid) < 0) {
				err(EXIT_FAILURE, "initgroups(%s, %d)",
				    as_user, pwd->pw_gid);
			}
			if (setuid(pwd->pw_uid) < 0) {
				err(EXIT_FAILURE, "setuid(%d)", pwd->pw_uid);
			}
		}
	}

	/*
	 * As with above, if we've been requested to change our umask,
	 * do it before we create any files.
	 */
	if (with_umask != NULL) {
		char *endcp;
		long val;

		errno = 0;
		val = strtol(with_umask, &endcp, 8);
		if (errno != 0 || *endcp != '\0' ||
		    val < 0 || val > 0777) {
			errx(EXIT_FAILURE, "Invalid umask: %s", with_umask);
		}
		nabud_umask = (mode_t)val;
		(void) umask(nabud_umask);
	} else {
		/* Just get the current value so we can report it. */
		nabud_umask = umask(0);
		(void) umask(nabud_umask);
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
	log_info("Running as UID %d, file creation mask %03o",
	    geteuid(), (int)nabud_umask);

	/* Set up our control connection. */
	control_init(NULL);

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
	conn_io_shutdown();
	log_info("Exiting. Thank you, come again!");
	log_fini();

	exit(0);
}
