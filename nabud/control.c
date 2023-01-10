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
 * Support for control messages.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libnabud/atom.h"
#include "libnabud/conn_io.h"
#include "libnabud/log.h"

#include "conn.h"
#include "control.h"
#include "image.h"

/*
 * control_serialize_channel --
 *	Serialize a channel object.
 */
static bool
control_serialize_channel(struct image_channel *chan, void *ctx)
{
	struct atom_list *list = ctx;
	const char *cp;
	bool rv;

	rv = atom_list_append_void(list, NABUCTL_OBJ_CHANNEL);

	rv = rv && atom_list_append_string(list, NABUCTL_CHAN_NAME, chan->name);

	/* XXX NABUCTL_CHAN_DISPLAY_NAME */

	rv = rv && atom_list_append_string(list, NABUCTL_CHAN_PATH, chan->path);

	if (chan->list_url != NULL) {
		rv = rv && atom_list_append_string(list, NABUCTL_CHAN_LISTURL,
		    chan->list_url);
	}

	if (chan->default_file != NULL) {
		rv = rv && atom_list_append_string(list,
		    NABUCTL_CHAN_DEFAULT_FILE, chan->default_file);
	}

	rv = rv && atom_list_append_number(list, NABUCTL_CHAN_NUMBER,
	    chan->number);

	switch (chan->type) {
	case IMAGE_CHANNEL_PAK:		cp = "PAK"; break;
	case IMAGE_CHANNEL_NABU:	cp = "NABU"; break;
	default:			cp = "???"; break;
	}
	rv = rv && atom_list_append_string(list, NABUCTL_CHAN_TYPE, cp);

	rv = rv && atom_list_append_string(list, NABUCTL_CHAN_TYPE,
	    chan->source->name);

	rv = rv && atom_list_append_done(list);

	return rv;
}

/*
 * control_serialize_connection --
 *	Serialize a connection object.
 */
static bool
control_serialize_connection(struct nabu_connection *conn, void *ctx)
{
	struct atom_list *list = ctx;
	const char *cp;
	bool rv;

	rv = atom_list_append_void(list, NABUCTL_OBJ_CONNECTION);

	switch (conn->type) {
	case CONN_TYPE_LISTENER:	cp = "Listener"; break;
	case CONN_TYPE_TCP:		cp = "TCP"; break;
	case CONN_TYPE_SERIAL:		cp = "Serial"; break;
	default:			cp = "???"; break;
	}
	rv = rv && atom_list_append_string(list, NABUCTL_CONN_TYPE, cp);

	rv = rv && atom_list_append_string(list, NABUCTL_CONN_NAME,
	    conn_name(conn));

	struct image_channel *chan;
	char selected_file[256];	/* reasonable limit */

	pthread_mutex_lock(&conn->mutex);
	chan = conn->l_channel;
	if (conn->l_selected_file != NULL) {
		size_t copylen = strlen(conn->l_selected_file);
		if (copylen >= sizeof(selected_file)) {
			copylen = sizeof(selected_file) - 1;
		}
		strncpy(selected_file, conn->l_selected_file,
		    sizeof(selected_file) - 1);
	} else {
		selected_file[0] = '\0';
	}
	pthread_mutex_unlock(&conn->mutex);

	if (chan != NULL) {
		rv = rv && atom_list_append_number(list, NABUCTL_CONN_CHANNEL,
		    chan->number);
	}

	if (selected_file[0] != '\0') {
		rv = rv && atom_list_append_string(list,
		    NABUCTL_CONN_SELECTED_FILE, selected_file);
	}

	switch (conn_state(conn)) {
	case CONN_STATE_OK:		cp = "OK"; break;
	case CONN_STATE_EOF:		cp = "EOF"; break;
	case CONN_STATE_CANCELLED:	cp = "CANCELLED"; break;
	case CONN_STATE_ABORTED:	cp = "ABORTED"; break;
	default:			cp = "???"; break;
	}
	rv = rv && atom_list_append_string(list, NABUCTL_CONN_STATE, cp);

	rv = rv && atom_list_append_done(list);

	return rv;
}

/*
 * control_req_list_channels --
 *	Handle a LIST CHANNELS request.
 */
static bool
control_req_list_channels(struct atom_list *reply_list)
{
	bool rv;

	rv = image_channel_enumerate(control_serialize_channel, reply_list);
	rv = rv && atom_list_append_done(reply_list);

	return rv;
}

/*
 * control_req_list_connections --
 *	Handle a LIST CONNECTIONS request.
 */
static bool
control_req_list_connections(struct atom_list *reply_list)
{
	bool rv;

	rv = conn_enumerate(control_serialize_connection, reply_list);
	rv = rv && atom_list_append_done(reply_list);

	return rv;
}

/*
 * control_connection_thread --
 *	Worker thread for control connections.
 */
static void *
control_connection_thread(void *arg)
{
	struct conn_io *conn = arg;
	struct atom_list req_list, reply_list;
	struct atom *req;
	bool ok;

	atom_list_init(&req_list);
	atom_list_init(&reply_list);

	for (ok = true; ok;) {
		atom_list_free(&req_list);
		atom_list_free(&reply_list);

		if (! atom_list_recv(conn, &req_list)) {
			/* Error already logged */
			break;
		}

		if (atom_list_count(&req_list)) {
			log_error("[%s] Empty request atom list??",
			    conn_io_name(conn));
			continue;
		}

		req = atom_list_next(&req_list, NULL);
		assert(req != NULL);

		switch (atom_tag(req)) {
		case NABUCTL_REQ_LIST_CHANNELS:
			log_debug("[%s] Got NABUCTL_REQ_LIST_CHANNELS.",
			    conn_io_name(conn));
			ok = control_req_list_channels(&reply_list);
			break;

		case NABUCTL_REQ_LIST_CONNECTIONS:
			log_debug("[%s] Got NABUCTL_REQ_LIST_CONNECTIONS.",
			    conn_io_name(conn));
			ok = control_req_list_connections(&reply_list);
			break;

		default:
			log_error("[%s] Unknown request atom: 0x%08x",
			    conn_io_name(conn), atom_tag(req));
			ok = atom_list_append_error(&reply_list);
		}

		if (ok) {
			ok = atom_list_send(conn, &reply_list);
		}
	}

	atom_list_free(&req_list);
	atom_list_free(&reply_list);

	conn_io_fini(conn);
	free(conn);

	return NULL;
}

#ifndef SUN_LEN
#define SUN_LEN(su) \
    (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif /* ! SUN_LEN */

/*
 * control_listen_thread --
 *	Worker thread that accepts new control connections.
 */
static void *
control_listen_thread(void *arg)
{
	struct conn_io *conn = arg;
	struct conn_io *newconn;
	const char *name;
	struct sockaddr_storage peerss;
	socklen_t peersslen;
	int sock;

	for (;;) {
		peersslen = sizeof(peerss);
		if (! conn_io_accept(conn, (struct sockaddr *)&peerss,
				     &peersslen, &sock)) {
			/* Error already logged. */
			break;
		}

		/* XXX LOCAL_PEEREID? */
		name = conn_io_name(conn);

		log_info("[%s] Creating new control connection.",
		    conn_io_name(conn));

		newconn = calloc(1, sizeof(*newconn));
		if (newconn == NULL) {
			log_error("Unable to allocate new connection.");
			close(sock);
			continue;
		}
		if (! conn_io_init(newconn, strdup(name), sock)) {
			/* Error already logged. */
			close(sock);
			continue;
		}
		if (! conn_io_start(newconn, control_connection_thread,
				    newconn)) {
			/* Error already logged. */
			conn_io_fini(newconn);
			continue;
		}
	}

	conn_io_fini(conn);
	free(conn);

	return NULL;
}

/*
 * control_init --
 *	Initialize the control connection.
 */
void
control_init(const char *path)
{
	struct sockaddr_un sun;
	struct conn_io *conn = NULL;
	int sock = -1;

	if (path == NULL) {
		path = NABUCTL_PATH_DEFAULT;
	}

	if (strlen(path) > sizeof(sun.sun_path)) {
		log_error("Path to control socket is too long: %s", path);
		return;
	}

	memset(&sun, 0, sizeof(sun));
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	sun.sun_family = AF_LOCAL;

	log_info("Creating control channel at %s", path);
	if (unlink(path) < 0) {
		if (errno != ENOENT) {
			log_error("unlink(%s) failed: %s", path,
			    strerror(errno));
			return;
		}
	}

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		return;
	}
	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock >= 0) {
		if (bind(sock, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0) {
			if (listen(sock, 8) == 0) {
				if (! conn_io_init(conn, strdup(path), sock)) {
					/* Error already logged. */
					goto bad;
				}
			} else {
				log_error("Unable to listen on %s: %s",
				    path, strerror(errno));
				goto bad;
			}
		} else {
			log_error("Unable to bind socket at %s: %s",
			    path, strerror(errno));
			goto bad;
		}
	} else {
		log_error("Unable to create local domain socket: %s",
		    strerror(errno));
		goto bad;
	}

	if (! conn_io_start(conn, control_listen_thread, conn)) {
		/* Error already logged. */
		conn_io_fini(conn);
	}
	return;

 bad:
	if (sock >= 0) {
		close(sock);
	}
	if (conn != NULL) {
		free(conn);
	}
}
