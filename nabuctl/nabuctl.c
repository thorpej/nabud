/*-
 * Copyright (c) 2023 Jason R. Thorpe.
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
 * nabuctl -- send control messages to nabud
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <err.h>	/* XXX HAVE_ERR_H-ize, please */
#include <setjmp.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libnabud/atom.h"
#include "libnabud/cli.h"
#include "libnabud/conn_io.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"
#include "libnabud/nabuctl_proto.h"

static struct conn_io server_conn;

static const char nabuctl_version[] = VERSION;

#define	FREE(x)								\
do {									\
	if ((x) != NULL) {						\
		free((x));						\
		x = NULL;						\
	}								\
} while (/*CONSTCOND*/0)

struct req_repl {
	struct atom_list req_list;
	struct atom_list reply_list;
};

static int
number_display_width(unsigned int number)
{
	if (number >= 100) {
		return 3;
	}
	if (number >= 10) {
		return 2;
	}
	return 1;
}

struct channel_desc {
	TAILQ_ENTRY(channel_desc) link;
	char		*name;
	char		*path;
	char		*list_url;
	char		*default_file;
	char		*type;
	char		*source;
	unsigned int	number;
};
static TAILQ_HEAD(, channel_desc) channel_list =
    TAILQ_HEAD_INITIALIZER(channel_list);
static int channel_number_width;
static int channel_name_width;

static struct channel_desc *
channel_desc_alloc(void)
{
	struct channel_desc *chan = calloc(1, sizeof(*chan));
	if (chan == NULL) {
		printf("Unable to allocate channel descriptor!");
		cli_quit();
	}
	return chan;
}

static void
channel_desc_free(struct channel_desc *chan)
{
	FREE(chan->name);
	FREE(chan->path);
	FREE(chan->list_url);
	FREE(chan->default_file);
	FREE(chan->type);
	FREE(chan->source);
	free(chan);
}

static void
channel_list_reset(void)
{
	struct channel_desc *chan, *nchan;

	TAILQ_FOREACH_SAFE(chan, &channel_list, link, nchan) {
		TAILQ_REMOVE(&channel_list, chan, link);
		channel_desc_free(chan);
	}
	channel_number_width = 0;
	channel_name_width = 0;
}

static void
channel_list_insert(struct channel_desc *chan)
{
	struct channel_desc *lchan, *prev_chan = NULL;
	size_t name_len;

	TAILQ_FOREACH(lchan, &channel_list, link) {
		if (chan->number > lchan->number) {
			prev_chan = lchan;
			continue;
		}
		if (chan->number == lchan->number) {
			log_info("Ignoring duplicate channel %u "
			    "(%s on %s)", chan->number, chan->name,
			    chan->source);
			channel_desc_free(chan);
			return;
		}
		if (chan->number < lchan->number) {
			TAILQ_INSERT_BEFORE(lchan, chan, link);
			goto out;
		}
	}
	if (prev_chan != NULL) {
		TAILQ_INSERT_AFTER(&channel_list, prev_chan, chan, link);
	} else {
		TAILQ_INSERT_HEAD(&channel_list, chan, link);
	}
out:
	name_len = strlen(chan->name);
	if (name_len > channel_name_width) {
		channel_name_width = (int)name_len;
	}
	if (number_display_width(chan->number) > channel_number_width) {
		channel_number_width = number_display_width(chan->number);
	}
}

static void
channel_list_enumerate(bool (*func)(struct channel_desc *, void *), void *ctx)
{
	struct channel_desc *chan;

	TAILQ_FOREACH(chan, &channel_list, link) {
		if (! (*func)(chan, ctx)) {
			break;
		}
	}
}

static struct atom *
channel_deserialize(struct atom_list *reply_list, struct atom *atom)
{
	struct channel_desc *chan = channel_desc_alloc();
	const char *cp;
	long val;

	while ((atom = atom_list_next(reply_list, atom)) != NULL) {
		switch (atom_tag(atom)) {
		case NABUCTL_CHAN_NAME:
			chan->name = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_NAME=%s", chan->name);
			break;

		case NABUCTL_CHAN_PATH:
			chan->path = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_PATH=%s", chan->path);
			break;

		case NABUCTL_CHAN_LISTURL:
			chan->list_url = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_LIST_URL=%s",
			    chan->list_url);
			break;

		case NABUCTL_CHAN_DEFAULT_FILE:
			chan->default_file = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_DEFAULT_FILE=%s",
			    chan->default_file);
			break;

		case NABUCTL_CHAN_NUMBER:
			cp = atom_dataref(atom);
			log_debug("Got NABUCTL_CHAN_NUMBER=%s", cp);
			val = strtol(cp, NULL, 0);
			if (val < 1 || val > 255) {
				log_error("Invalid channel number: %s", cp);
				atom = NULL;
				goto out;
			}
			chan->number = (unsigned int)val;
			break;

		case NABUCTL_CHAN_TYPE:
			chan->type = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_TYPE=%s", chan->type);
			break;

		case NABUCTL_CHAN_SOURCE:
			chan->source = atom_consume(atom);
			log_debug("Got NABUCTL_CHAN_SOURCE=%s", chan->source);
			break;

		case NABUCTL_DONE:	/* done with this object */
			log_debug("Got NABUCTL_DONE");
			goto out;

		default:
			log_error("Unexpected atom tag=0x%08x",
			    atom_tag(atom));
		}
	}
 out:
	if (atom != NULL) {
		channel_list_insert(chan);
	} else {
		channel_desc_free(chan);
	}
	return atom;
}

struct connection_desc {
	TAILQ_ENTRY(connection_desc) link;
	char		*name;
	char		*type;
	char		*state;
	char		*selected_file;
	unsigned int	channel;
	unsigned int	number;
};
static TAILQ_HEAD(, connection_desc) connection_list =
    TAILQ_HEAD_INITIALIZER(connection_list);
static int connection_count;
static int connection_number_width;
static int connection_type_width;

static struct connection_desc *
connection_desc_alloc(void)
{
	struct connection_desc *conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		printf("Unable to allocate connection descriptor!");
		cli_quit();
	}
	return conn;
}

static void
connection_desc_free(struct connection_desc *conn)
{
	FREE(conn->name);
	FREE(conn->type);
	FREE(conn->state);
	FREE(conn->selected_file);
	free(conn);
}

static void
connection_list_reset(void)
{
	struct connection_desc *conn, *nconn;

	TAILQ_FOREACH_SAFE(conn, &connection_list, link, nconn) {
		TAILQ_REMOVE(&connection_list, conn, link);
		connection_desc_free(conn);
	}
	connection_count = 0;
	connection_number_width = 0;
	connection_type_width = 0;
}

static void
connection_list_insert(struct connection_desc *conn)
{
	size_t type_length = strlen(conn->type);
	if (type_length > connection_type_width) {
		connection_type_width = (int)type_length;
	}
	conn->number = ++connection_count;
	if (number_display_width(conn->number) > connection_number_width) {
		connection_number_width = number_display_width(conn->number);
	}
	TAILQ_INSERT_TAIL(&connection_list, conn, link);
}

static void
connection_list_enumerate(bool (*func)(struct connection_desc *, void *),
    void *ctx)
{
	struct connection_desc *conn;

	TAILQ_FOREACH(conn, &connection_list, link) {
		if (! (*func)(conn, ctx)) {
			break;
		}
	}
}

static struct atom *
connection_deserialize(struct atom_list *reply_list, struct atom *atom)
{
	struct connection_desc *conn = connection_desc_alloc();
	const char *cp;
	long val;

	while ((atom = atom_list_next(reply_list, atom)) != NULL) {
		switch (atom_tag(atom)) {
		case NABUCTL_CONN_NAME:
			conn->name = atom_consume(atom);
			log_debug("Got NABUCTL_CONN_NAME=%s", conn->name);
			break;

		case NABUCTL_CONN_TYPE:
			conn->type = atom_consume(atom);
			log_debug("Got NABUCTL_CONN_TYPE=%s", conn->type);
			break;

		case NABUCTL_CONN_STATE:
			conn->state = atom_consume(atom);
			log_debug("Got NABUCTL_CONN_STATE=%s", conn->state);
			break;

		case NABUCTL_CONN_CHANNEL:
			cp = atom_dataref(atom);
			log_debug("Got NABUCTL_CONN_CHANNEL=%s", cp);
			val = strtol(cp, NULL, 0);
			if (val < 1 || val > 255) {
				log_error("Invalid channel number: %s", cp);
				atom = NULL;
				goto out;
			}
			conn->channel = (unsigned int)val;
			break;

		case NABUCTL_CONN_SELECTED_FILE:
			conn->selected_file = atom_consume(atom);
			log_debug("Got NABUCTL_CONN_SELECTED_FILE=%s",
			    conn->selected_file);
			break;

		case NABUCTL_DONE:	/* done with this object */
			log_debug("Got NABUCTL_DONE");
			goto out;

		default:
			log_error("Unexpected atom tag=0x%08x",
			    atom_tag(atom));
		}
	}
 out:
	if (atom != NULL) {
		connection_list_insert(conn);
	} else {
		connection_desc_free(conn);
	}
	return atom;
}

static void
rr_init(struct req_repl *rr)
{
	atom_list_init(&rr->req_list);
	atom_list_init(&rr->reply_list);
}

static void
rr_done(struct req_repl *rr)
{
	atom_list_free(&rr->req_list);
	atom_list_free(&rr->reply_list);
}

static void
rr_req_build_failed(struct req_repl *rr)
{
	atom_list_free(&rr->req_list);
	log_error("Building request atom list failed!");
}

static void
server_disconnected(void)
{
	printf("Server disconnected!\n");
	cli_quit();
}

static void
server_send(struct atom_list *list)
{
	if (! atom_list_send(&server_conn, list)) {
		server_disconnected();
	}
}

static void
server_recv(struct atom_list *list)
{
	if (! atom_list_recv(&server_conn, list)) {
		server_disconnected();
	}
}

static void
say_hello(void)
{
	struct req_repl rr;
	struct atom *atom;

	rr_init(&rr);
	if (atom_list_append_string(&rr.req_list, NABUCTL_REQ_HELLO,
				    nabuctl_version) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_data_type(atom) != NABUCTL_TYPE_STRING) {
		log_error("Expected type %s, got %s.",
		    atom_typedesc(NABUCTL_TYPE_STRING),
		    atom_typedesc(atom_data_type(atom)));
		goto out;
	}
	char *server_version = atom_dataref(atom);

	printf("Server version: %s\n", server_version);
	if (strcmp(server_version, nabuctl_version) != 0) {
		log_error("Version mismatch (client %s, server %s).",
		    nabuctl_version, server_version);
	}
 out:
	rr_done(&rr);
}

static bool
command_exit(int argc, char *argv[])
{
	return true;			/* EOF! */
}

static bool
channel_print_cb(struct channel_desc *chan, void *ctx)
{
	printf("%-*u - %-*s (%s)\n", channel_number_width, chan->number,
	    channel_name_width, chan->name,
	    chan->source);
	return true;
}

static bool
command_list_channels(int argc, char *argv[])
{
	struct req_repl rr;
	struct atom *atom;

	rr_init(&rr);
	if (atom_list_append_void(&rr.req_list, NABUCTL_REQ_LIST_CHANNELS) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		cli_throw();
	}

	server_recv(&rr.reply_list);
	channel_list_reset();

	for (atom = NULL;;) {
		atom = atom_list_next(&rr.reply_list, atom);
		if (atom == NULL) {
			log_error("Unexpected end of atom list.");
		}
		switch (atom_tag(atom)) {
		case NABUCTL_DONE:
			log_debug("Finished enumerating channel list.");
			goto out;

		case NABUCTL_OBJ_CHANNEL:
			log_debug("Deserializing channel.");
			atom = channel_deserialize(&rr.reply_list, atom);
			if (atom == NULL) {
				/* Error already reported. */
				goto out;
			}
			continue;

		default:
			log_error("Unexpected atom tag=0x%08x",
			    atom_tag(atom));
			break;
		}
	}
 out:
	rr_done(&rr);

	channel_list_enumerate(channel_print_cb, NULL);

	return false;
}

static bool
connection_print_cb(struct connection_desc *conn, void *ctx)
{
	char channelstr[sizeof("[4294967295]")];

	if (conn->channel != 0) {
		snprintf(channelstr, sizeof(channelstr),
		    "[%u]", conn->channel);
	} else {
		channelstr[0] = '\0';
	}

	printf("%-*u - %-*s %-*s %s\n", connection_number_width, conn->number,
	    connection_type_width, conn->type,
	    channel_number_width + 2, channelstr,
	    conn->name);
	return true;
}

static bool
command_list_connections(int argc, char *argv[])
{
	struct req_repl rr;
	struct atom *atom;

	rr_init(&rr);
	if (atom_list_append_void(&rr.req_list, NABUCTL_REQ_LIST_CONNECTIONS) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		cli_throw();
	}

	server_recv(&rr.reply_list);
	connection_list_reset();

	for (atom = NULL;;) {
		atom = atom_list_next(&rr.reply_list, atom);
		if (atom == NULL) {
			log_error("Unexpected end of atom list.");
		}
		switch (atom_tag(atom)) {
		case NABUCTL_DONE:
			log_debug("Finished enumerating channel list.");
			goto out;

		case NABUCTL_OBJ_CONNECTION:
			log_debug("Deserializing connection.");
			atom = connection_deserialize(&rr.reply_list, atom);
			if (atom == NULL) {
				/* Error already reported. */
				goto out;
			}
			continue;

		default:
			log_error("Unexpected atom tag=0x%08x",
			    atom_tag(atom));
			break;
		}
	}
 out:
	rr_done(&rr);

	connection_list_enumerate(connection_print_cb, NULL);

	return false;
}

static bool
command_verb_noun_unknown(int argc, char *argv[])
{
	printf("Don't know how to %s '%s'.  Try '%s ?'.\n",
	    argv[0], argv[1], argv[0]);
	return false;
}

static const struct cmdtab list_cmdtab[] = {
	{ .name = "channels",		.func = command_list_channels },
	{ .name = "connections",	.func = command_list_connections },

	{ .name = "help",		.func = command_help,
					.suppress_in_help = true },
	{ .name = "?",			.func = command_help,
					.suppress_in_help = true },

	CMDTAB_EOL(command_verb_noun_unknown)
};

static bool
command_list(int argc, char *argv[])
{
	return cli_subcommand(list_cmdtab, argc, argv, 1);
}

static bool	command_help(int, char *[]);

static const struct cmdtab cmdtab[] = {
	{ .name = "exit",		.func = command_exit },
	{ .name = "quit",		.func = command_exit },

	{ .name = "help",		.func = command_help },
	{ .name = "?",			.func = command_help },

	{ .name = "list",		.func = command_list },

	CMDTAB_EOL(cli_command_unknown)
};

static bool
command_help(int argc, char *argv[])
{
	return cli_help(cmdtab);
}

static bool
nabuctl_cliprep(void *ctx)
{
	/* Do a HELLO exchange with the server. */
	say_hello();

	return true;
}

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "%s version %s\n", getprogname(), nabuctl_version);
	fprintf(stderr, "usage: %s\n", getprogname());
	exit(EXIT_FAILURE);
}

#ifndef SUN_LEN         
#define	SUN_LEN(su) \
    (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))  
#endif /* ! SUN_LEN */              

int
main(int argc, char *argv[])
{
	const char *path = NABUCTL_PATH_DEFAULT;
	int sock;

	setprogname(argv[0]);

	if (argc != 1) {
		usage();
		/* NOTREACHED */
	}

	/* Set up our initial signal state. */
	(void) signal(SIGPIPE, SIG_IGN);

	/* Logging system is required for conn_io. */
	if (! log_init(NULL, LOG_OPT_FOREGROUND)) {
		errx(EXIT_FAILURE, "log_init() failed");
	}

	/* Connect to the server. */
	struct sockaddr_un sun;
	if (strlen(path) > sizeof(sun.sun_path)) {
		errx(EXIT_FAILURE, "Path to control socket is too long: %s",
		    path);
	}
	memset(&sun, 0, sizeof(sun));
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));
#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun.sun_len = SUN_LEN(&sun);
#endif
	sun.sun_family = AF_LOCAL;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		err(EXIT_FAILURE, "socket(PF_LOCAL, SOCK_STREAM, 0)");
	}

	if (connect(sock, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
		err(EXIT_FAILURE, "connect(%s)", path);
	}

	if (! conn_io_init(&server_conn, strdup(path), sock)) {
		/* Error already reported. */
		close(sock);
		exit(EXIT_FAILURE);
	}
	if (! conn_io_start(&server_conn, NULL, NULL)) {
		/* Error already reported. */
		conn_io_fini(&server_conn);
		exit(EXIT_FAILURE);
	}

	/* Enter the command loop. */
	cli_commands(getprogname(), cmdtab, nabuctl_cliprep, NULL));

	printf("Thanks for visiting the land of NABU!\n");
	exit(0);
}
