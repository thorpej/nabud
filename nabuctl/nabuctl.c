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
#include <limits.h>
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
#include "libnabud/listing.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"
#include "libnabud/nabuctl_proto.h"

static struct conn_io server_conn;

static const char nabuctl_version[] = VERSION;

/*****************************************************************************
 * RANDOM USEFUL STUFF
 *****************************************************************************/

#define	FREE(x)								\
do {									\
	if ((x) != NULL) {						\
		free((x));						\
		x = NULL;						\
	}								\
} while (/*CONSTCOND*/0)

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

static bool
parse_number(const char *arg, const char *what,
    long lower, long upper, long *valp)
{
	long val;

	val = strtol(arg, NULL, 10);
	if (val < lower || val > upper) {
		printf("Invalid %s: '%s'; must be between %ld - %ld\n",
		    what, arg, lower, upper);
		return false;
	}
	*valp = val;
	return true;
}

static const char *
enabledstr(bool val)
{
	return val ? "enabled" : "disabled";
}

/*****************************************************************************
 * SERVER COMMUNICATION STUFF
 *****************************************************************************/

struct req_repl {
	struct atom_list req_list;
	struct atom_list reply_list;
};

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

/*****************************************************************************
 * FILE STUFF
 *****************************************************************************/

static bool
fileno_parse(const char *arg, uint32_t *filenop)
{
	long val;

	val = strtol(arg, NULL, 10);
	if (val < 0 || val > INT32_MAX) {
		printf("Invalid file number: %s", arg);
		return false;
	}
	*filenop = (uint32_t)val;
	return true;
}

/*****************************************************************************
 * CHANNEL STUFF
 *****************************************************************************/

struct channel_desc {
	TAILQ_ENTRY(channel_desc) link;
	char		*name;
	char		*path;
	char		*list_url;
	char		*default_file;
	char		*type;
	char		*source;
	struct listing	*listing;
	unsigned int	number;
	bool		retronet_enabled;
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

static struct channel_desc *
channel_lookup(unsigned int number)
{
	struct channel_desc *chan;

	TAILQ_FOREACH(chan, &channel_list, link) {
		if (chan->number == number) {
			return chan;
		}
	}
	return NULL;
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
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_NAME=%s", chan->name);
			break;

		case NABUCTL_CHAN_PATH:
			chan->path = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_PATH=%s", chan->path);
			break;

		case NABUCTL_CHAN_LISTURL:
			chan->list_url = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_LIST_URL=%s", chan->list_url);
			break;

		case NABUCTL_CHAN_DEFAULT_FILE:
			chan->default_file = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_DEFAULT_FILE=%s",
			    chan->default_file);
			break;

		case NABUCTL_CHAN_NUMBER:
			cp = atom_dataref(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_NUMBER=%s", cp);
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
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_TYPE=%s", chan->type);
			break;

		case NABUCTL_CHAN_SOURCE:
			chan->source = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_SOURCE=%s", chan->source);
			break;

		case NABUCTL_CHAN_RETRONET_EXTENSIONS:
			chan->retronet_enabled = atom_bool_value(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CHAN_RETRONET_EXTENSIONS=%d",
			    chan->retronet_enabled);
			break;

		case NABUCTL_DONE:	/* done with this object */
			log_debug(LOG_SUBSYS_CONTROL, "Got NABUCTL_DONE");
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

static void
channel_list_fetch(void)
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
			cli_throw();
		}
		switch (atom_tag(atom)) {
		case NABUCTL_DONE:
			log_debug(LOG_SUBSYS_CONTROL,
			    "Finished enumerating channel list.");
			goto out;

		case NABUCTL_OBJ_CHANNEL:
			log_debug(LOG_SUBSYS_CONTROL, "Deserializing channel.");
			atom = channel_deserialize(&rr.reply_list, atom);
			if (atom == NULL) {
				/* Error already reported. */
				cli_throw();
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
}

static bool
channel_parse(const char *arg, uint32_t *chanp)
{
	struct channel_desc *chan;
	long val;

	if (TAILQ_FIRST(&channel_list) == NULL) {
		printf("No channels.\n");
		return false;
	}

	if (! parse_number(arg, "channel", 1, 255, &val)) {
		/* Error already reported. */
		return false;
	}

	TAILQ_FOREACH(chan, &channel_list, link) {
		if (chan->number == (unsigned int)val) {
			*chanp = chan->number;
			return true;
		}
	}

	printf("Unknown channel: %ld\n", val);
	return false;
}

static void
channel_clear_cache(uint32_t channel)
{
	struct req_repl rr;
	struct atom *atom;

	struct channel_desc *chan = channel_lookup(channel);
	assert(chan != NULL);

	printf("Clearing cache on '%s' (%s).\n", chan->name, chan->source);

	rr_init(&rr);

	if (atom_list_append_number(&rr.req_list,
				    NABUCTL_REQ_CHAN_CLEAR_CACHE,
				    chan->number) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_tag(atom) == NABUCTL_ERROR) {
		printf("*** Failed to clear cache! ***\n");
	}
 out:
	rr_done(&rr);

	/* If we have listing data, free it. */
	if (chan->listing != NULL) {
		listing_free(chan->listing);
		chan->listing = NULL;
	}
}

static void
channel_fetch_listing(uint32_t channel)
{
	struct req_repl rr;
	struct atom *atom;

	struct channel_desc *chan = channel_lookup(channel);
	assert(chan != NULL);

	if (chan->listing != NULL) {
		listing_free(chan->listing);
		chan->listing = NULL;
	}

	if (chan->list_url == NULL) {
 		return;
	}

	rr_init(&rr);

	if (atom_list_append_number(&rr.req_list,
				    NABUCTL_REQ_CHAN_FETCH_LISTING,
				    chan->number) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_tag(atom) == NABUCTL_ERROR) {
		printf("*** Error fetching listing! ***\n");
	} else if (atom_tag(atom) == NABUCTL_TYPE_BLOB) {
		chan->listing = listing_create(atom_consume(atom),
		    atom_length(atom));
	}
 out:
	rr_done(&rr);
}

static void
channel_display_listing(uint32_t channel)
{
	struct channel_desc *chan = channel_lookup(channel);
	assert(chan != NULL);

	channel_fetch_listing(channel);

	if (chan->listing == NULL) {
		printf("Channel %u (%s on %s) has no listing.\n",
		    chan->number, chan->name, chan->source);
		return;
	}

	struct listing_category *c;
	struct listing_entry *e;
	TAILQ_FOREACH(c, &chan->listing->categories, link) {
		printf("=====> %s\n", c->name);
		TAILQ_FOREACH(e, &c->entries, category_link) {
			printf("%-*u - %-*s %s\n",
			   number_display_width(chan->listing->next_fileno - 1),
			   e->number, chan->listing->longest_name, e->name,
			   e->desc != NULL ? e->desc : "");
		}
	}
}

/*****************************************************************************
 * CONNECTION STUFF
 *****************************************************************************/

struct connection_desc {
	TAILQ_ENTRY(connection_desc) link;
	char		*name;
	char		*type;
	char		*state;
	char		*selected_file;
	char		*file_root;
	unsigned int	channel;
	unsigned int	number;
	bool		retronet_enabled;
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
	FREE(conn->file_root);
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

static struct connection_desc *
connection_lookup(unsigned int number)
{
	struct connection_desc *conn;

	TAILQ_FOREACH(conn, &connection_list, link) {
		if (conn->number == number) {
			return conn;
		}
	}
	return NULL;
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
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_NAME=%s", conn->name);
			break;

		case NABUCTL_CONN_TYPE:
			conn->type = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_TYPE=%s", conn->type);
			break;

		case NABUCTL_CONN_STATE:
			conn->state = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_STATE=%s", conn->state);
			break;

		case NABUCTL_CONN_CHANNEL:
			cp = atom_dataref(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_CHANNEL=%s", cp);
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
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_SELECTED_FILE=%s",
			    conn->selected_file);
			break;

		case NABUCTL_CONN_RETRONET_EXTENSIONS:
			conn->retronet_enabled = atom_bool_value(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_RETRONET_EXTENSIONS=%d",
			    conn->retronet_enabled);
			break;

		case NABUCTL_CONN_FILE_ROOT:
			conn->file_root = atom_consume(atom);
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_CONN_FILE_ROOT=%s",
			    conn->file_root);
			break;

		case NABUCTL_DONE:	/* done with this object */
			log_debug(LOG_SUBSYS_CONTROL,
			    "Got NABUCTL_DONE");
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
connection_list_fetch(void)
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
			cli_throw();
		}
		switch (atom_tag(atom)) {
		case NABUCTL_DONE:
			log_debug(LOG_SUBSYS_CONTROL,
			    "Finished enumerating channel list.");
			goto out;

		case NABUCTL_OBJ_CONNECTION:
			log_debug(LOG_SUBSYS_CONTROL,
			    "Deserializing connection.");
			atom = connection_deserialize(&rr.reply_list, atom);
			if (atom == NULL) {
				/* Error already reported. */
				cli_throw();
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
}

static bool
connection_parse(const char *arg, uint32_t *connp)
{
	long val;

	if (connection_count < 1) {
		printf("No connections.\n");
		return false;
	}

	if (! parse_number(arg, "connection", 1, connection_count, &val)) {
		/* Error already reported. */
		return false;
	}

	*connp = (uint32_t)val;
	return true;
}

static void
connection_cancel(uint32_t connection)
{
	struct req_repl rr;
	struct atom *atom;

	struct connection_desc *conn = connection_lookup(connection);
	assert(conn != NULL);

	printf("%s: Cancelling connection.\n", conn->name);

	rr_init(&rr);

	if (atom_list_append_string(&rr.req_list,
				    NABUCTL_REQ_CONN_CANCEL,
				    conn->name) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_tag(atom) == NABUCTL_ERROR) {
		printf("*** Failed to cancel connection! ***\n");
	}
 out:
	rr_done(&rr);
}

static void
connection_change_channel(uint32_t connection, uint32_t channel)
{
	struct req_repl rr;
	struct atom *atom;

	struct connection_desc *conn = connection_lookup(connection);
	assert(conn != NULL);

	struct channel_desc *chan = channel_lookup(channel);
	assert(chan != NULL);

	printf("%s: Selecting channel '%s' on %s.\n",
	    conn->name, chan->name, chan->source);

	rr_init(&rr);

	if (atom_list_append_string(&rr.req_list,
				    NABUCTL_REQ_CONN_CHANGE_CHANNEL,
				    conn->name) &&
	    atom_list_append_number(&rr.req_list,
				    NABUCTL_TYPE_NUMBER,
				    chan->number) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_tag(atom) == NABUCTL_ERROR) {
		printf("*** Changing channel failed! ***\n");
	}
 out:
	rr_done(&rr);
}

static void
connection_select_file(uint32_t connection, uint32_t fileno)
{
	struct req_repl rr;
	struct atom *atom;

	struct connection_desc *conn = connection_lookup(connection);
	assert(conn != NULL);

	struct channel_desc *chan = channel_lookup(conn->channel);
	assert(chan != NULL);

	if (chan->listing == NULL) {
		channel_fetch_listing(conn->channel);
		if (chan->listing == NULL) {
			printf("No files available.\n");
			return;
		}
	}

	struct listing_entry *e = listing_entry_lookup(chan->listing, fileno);
	if (e == NULL) {
		printf("Unknown file number: %u\n", fileno);
		return;
	}

	printf("%s: Selecting file '%s'\n", conn->name, e->name);

	rr_init(&rr);

	if (atom_list_append_string(&rr.req_list,
				    NABUCTL_REQ_CONN_SELECT_FILE,
				    conn->name) &&
	    atom_list_append_string(&rr.req_list,
				    NABUCTL_TYPE_STRING,
				    e->name) &&
	    atom_list_append_done(&rr.req_list)) {
		server_send(&rr.req_list);
	} else {
		rr_req_build_failed(&rr);
		goto out;
	}

	server_recv(&rr.reply_list);
	atom = atom_list_next(&rr.reply_list, NULL);
	if (atom_tag(atom) == NABUCTL_ERROR) {
		printf("*** Failed to select file! ***\n");
	}
 out:
	rr_done(&rr);
}

/*****************************************************************************
 * COMMAND STUFF
 *****************************************************************************/

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
	channel_list_fetch();
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
	connection_list_fetch();
	connection_list_enumerate(connection_print_cb, NULL);
	return false;
}

static bool
command_list_usage(int argc, char *argv[])
{
	printf("Usage:\n");
	printf("\tlist channels\n");
	printf("\tlist connections\n");
	return false;
}

static const struct cmdtab list_cmdtab[] = {
	{ .name = "channels",		.func = command_list_channels },
	{ .name = "connections",	.func = command_list_connections },

	CMDTAB_EOL(command_list_usage)
};

static bool
command_list(int argc, char *argv[])
{
	if (argc < 2) {
		return command_list_usage(argc, argv);
	}
	return cli_subcommand(list_cmdtab, argc, argv, 1);
}

static bool
command_show_usage(int argc, char *argv[])
{
	printf("Usage:\n");
	printf("\tshow channel <number>\n");
	printf("\tshow connection <number>\n");
	printf("\tshow all channels\n");
	printf("\tshow all connections\n");
	return false;
}

static void
show_one_channel(struct channel_desc *chan)
{
	printf("Channel %u:\n", chan->number);
	printf("        Name: %s\n", chan->name);
	printf("      Source: %s\n", chan->source);
	printf("        Path: %s\n", chan->path);
	printf("        Type: %s\n", chan->type);
	if (chan->default_file != NULL) {
		printf("Default file: %s\n", chan->default_file);
	}
	if (chan->list_url != NULL) {
		printf(" Listing URL: %s\n", chan->list_url);
	}
	printf("    RetroNet: %s\n", enabledstr(chan->retronet_enabled));
}

static bool
command_show_channel(int argc, char *argv[])
{
	struct channel_desc *chan;
	uint32_t channel;

	if (! channel_parse(argv[2], &channel)) {
		/* Error already reported. */
		return false;
	}

	channel_list_fetch();
	if ((chan = channel_lookup(channel)) == NULL) {
		printf("Invalid channel: %s\n", argv[2]);
		return false;
	}
	show_one_channel(chan);

	return false;
}

static bool
command_show_all_channels(int argc, char *argv[])
{
	struct channel_desc *chan;
	bool want_crlf = false;

	TAILQ_FOREACH(chan, &channel_list, link) {
		if (want_crlf) {
			printf("\n");
		}
		show_one_channel(chan);
		want_crlf = true;
	}
	return false;
}

static void
show_one_connection(struct connection_desc *conn)
{
	printf("Connection %u:\n", conn->number);
	printf("         Name: %s\n", conn->name);
	printf("         Type: %s\n", conn->type);
	printf("        State: %s\n", conn->state);
	if (conn->channel != 0) {
		printf("      Channel: %u\n", conn->channel);
	}
	if (conn->selected_file != NULL) {
		printf("Selected file: %s\n", conn->selected_file);
	}
	if (conn->file_root != NULL) {
		printf(" Storage area: %s\n", conn->file_root);
	}
	printf("     RetroNet: %s\n", enabledstr(conn->retronet_enabled));
}

static bool
command_show_connection(int argc, char *argv[])
{
	struct connection_desc *conn;
	uint32_t connection;

	if (! connection_parse(argv[2], &connection)) {
		/* Error already reported. */
		return false;
	}

	connection_list_fetch();
	if ((conn = connection_lookup(connection)) == NULL) {
		printf("Invalid connection: %s\n", argv[2]);
		return false;
	}
	show_one_connection(conn);

	return false;
}

static bool
command_show_all_connections(int argc, char *argv[])
{
	struct connection_desc *conn;
	bool want_crlf = false;

	TAILQ_FOREACH(conn, &connection_list, link) {
		if (want_crlf) {
			printf("\n");
		}
		show_one_connection(conn);
		want_crlf = true;
	}
	return false;
}

static const struct cmdtab show_all_cmdtab[] = {
	{ .name = "channels",		.func = command_show_all_channels },
	{ .name = "connections",	.func = command_show_all_connections },

	CMDTAB_EOL(command_show_usage)
};

static bool
command_show_all(int argc, char *argv[])
{
	return cli_subcommand(show_all_cmdtab, argc, argv, 2);
}

static const struct cmdtab show_cmdtab[] = {
	{ .name = "all",		.func = command_show_all },
	{ .name = "channel",		.func = command_show_channel },
	{ .name = "connection",		.func = command_show_connection },

	CMDTAB_EOL(command_show_usage)
};

static bool
command_show(int argc, char *argv[])
{
	if (argc < 3) {
		return command_show_usage(argc, argv);
	}
	return cli_subcommand(show_cmdtab, argc, argv, 1);
}

static bool
command_connection_usage(int argc, char *argv[])
{
	printf("Usage:\n");
	printf("\tconnection <number> cancel\n");
	printf("\tconnection <number> channel <number>\n");
	printf("\tconnection <number> listing\n");
	printf("\tconnection <number> file <number>\n");
	return false;
}

static bool
command_connection_cancel(int argc, char *argv[])
{
	uint32_t conn;

	if (! connection_parse(argv[1], &conn)) {
		/* Error already reported. */
		return false;
	}
	connection_cancel(conn);
	return false;
}

static bool
command_connection_channel(int argc, char *argv[])
{
	uint32_t conn, chan;

	if (argc < 4) {
		return command_connection_usage(argc, argv);
	}

	if (! connection_parse(argv[1], &conn) ||
	    ! channel_parse(argv[3], &chan)) {
		/* Error already reported. */
		return false;
	}
	connection_change_channel(conn, chan);
	return false;
}

static bool
command_connection_file(int argc, char *argv[])
{
	struct connection_desc *conn;
	struct channel_desc *chan;
	uint32_t connection, fileno;

	if (argc < 4) {
		return command_connection_usage(argc, argv);
	}

	if (! connection_parse(argv[1], &connection) ||
	    ! fileno_parse(argv[3], &fileno)) {
		/* Error already reported. */
		return false;
	}
	if ((conn = connection_lookup(connection)) == NULL) {
		printf("Invalid connection: %s\n", argv[1]);
		return false;
	}
	if (conn->channel == 0) {
		printf("No channel selected.\n");
		return false;
	}
	chan = channel_lookup(conn->channel);
	if (chan == NULL) {
		printf("Channel %u not found.\n", conn->channel);
		return false;
	}
	connection_select_file(connection, fileno);
	return false;
}

static bool
command_connection_listing(int argc, char *argv[])
{
	struct connection_desc *conn;
	struct channel_desc *chan;
	uint32_t connection;

	if (argc < 3) {
		return command_connection_usage(argc, argv);
	}

	if (! connection_parse(argv[1], &connection)) {
		/* Error already reported. */
		return false;
	}
	if ((conn = connection_lookup(connection)) == NULL) {
		printf("Invalid connection: %s\n", argv[1]);
		return false;
	}
	if (conn->channel == 0) {
		printf("No channel selected.\n");
		return false;
	}
	chan = channel_lookup(conn->channel);
	if (chan == NULL) {
		printf("Channel %u not found.\n", conn->channel);
		return false;
	}
	channel_display_listing(conn->channel);
	return false;
}

static const struct cmdtab connection_cmdtab[] = {
	{ .name = "cancel",		.func = command_connection_cancel },
	{ .name = "channel",		.func = command_connection_channel },
	{ .name = "listing",		.func = command_connection_listing },
	{ .name = "file",		.func = command_connection_file },

	CMDTAB_EOL(command_connection_usage)
};

static bool
command_connection(int argc, char *argv[])
{
	if (argc < 3) {
		return command_connection_usage(argc, argv);
	}
	return cli_subcommand(connection_cmdtab, argc, argv, 2);
}

static bool
command_channel_usage(int argc, char *argv[])
{
	printf("Usage:\n");
	printf("\tchannel <number> clear-cache\n");
	printf("\tchannel <number> listing\n");
	return false;
}

static bool
command_channel_clear_cache(int argc, char *argv[])
{
	uint32_t chan;

	assert(argc >= 2);
	if (! channel_parse(argv[1], &chan)) {
		/* Error already reported. */
		return false;
	}
	channel_clear_cache(chan);
	return false;
}

static bool
command_channel_listing(int argc, char *argv[])
{
	uint32_t channel;

	if (argc < 3) {
		return command_channel_usage(argc, argv);
	}

	if (! channel_parse(argv[1], &channel)) {
		/* Error already reported. */
		return false;
	}
	channel_display_listing(channel);
	return false;
}

static const struct cmdtab channel_cmdtab[] = {
	{ .name = "clear-cache",	.func = command_channel_clear_cache },
	{ .name = "listing",		.func = command_channel_listing },

	CMDTAB_EOL(command_channel_usage)
};

static bool
command_channel(int argc, char *argv[])
{
	if (argc < 3) {
		return command_channel_usage(argc, argv);
	}
	return cli_subcommand(channel_cmdtab, argc, argv, 2);
}

static bool	command_help(int, char *[]);

static const struct cmdtab cmdtab[] = {
	{ .name = "exit",		.func = command_exit },
	{ .name = "quit",		.func = command_exit },

	{ .name = "help",		.func = command_help },
	{ .name = "?",			.func = command_help },

	{ .name = "channel",		.func = command_channel },
	{ .name = "connection",		.func = command_connection },

	{ .name = "list",		.func = command_list },
	{ .name = "show",		.func = command_show },

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

	/*
	 * Pre-fetch the channel and server list so we can get going
	 * right away without listing first.
	 */
	channel_list_fetch();
	connection_list_fetch();

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
	unsigned int logopts = 0;
	int ch, sock;

	setprogname(argv[0]);

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			log_debug_enable("any");
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

	/* Set up our initial signal state. */
	(void) signal(SIGPIPE, SIG_IGN);

	/* Logging system is required for conn_io. */
	if (! log_init(NULL, logopts | LOG_OPT_FOREGROUND)) {
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
	cli_commands(getprogname(), cmdtab, nabuctl_cliprep, NULL);
	exit(0);
}
