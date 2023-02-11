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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#if defined(LOCAL_PEERCRED) && defined(HAVE_SYS_UCRED_H)
#include <sys/ucred.h>
#endif /* LOCAL_PEERCRED && HAVE_SYS_UCRED_H */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "libnabud/atom.h"
#include "libnabud/conn_io.h"
#include "libnabud/missing.h"
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

	rv = rv && atom_list_append_string(list, NABUCTL_CHAN_SOURCE,
	    chan->source->name);

	rv = rv && atom_list_append_bool(list, NABUCTL_CHAN_RETRONET_EXTENSIONS,
	    chan->retronet_enabled);

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

	rv = rv && atom_list_append_bool(list, NABUCTL_CONN_RETRONET_EXTENSIONS,
	    conn->retronet_enabled);

	if (conn->file_root != NULL) {
		rv = rv && atom_list_append_string(list,
		    NABUCTL_CONN_FILE_ROOT, conn->file_root);
	}

	rv = rv && atom_list_append_done(list);

	return rv;
}

/*
 * control_req_hello --
 *	Handle a HELLO request.
 */
static bool
control_req_hello(struct conn_io *conn, struct atom *req,
    struct atom_list *req_list, struct atom_list *reply_list)
{
	extern const char nabud_version[];
	bool rv;

	if (atom_data_type(req) != NABUCTL_TYPE_STRING) {
		log_error("[%s] Expected %s, got %s",
		    conn_io_name(conn),
		    atom_typedesc(NABUCTL_TYPE_STRING),
		    atom_typedesc(atom_data_type(req)));
		return false;
	}

	char *client_version = atom_dataref(req);
	log_debug("[%s] Client version: %s", conn_io_name(conn),
	    client_version);

	if (strcmp(client_version, nabud_version) != 0) {
		log_info("[%s] Client version (%s) does not match %s (%s).",
		    conn_io_name(conn), client_version, getprogname(),
		    nabud_version);
	}

	rv = atom_list_append_string(reply_list, NABUCTL_TYPE_STRING,
	    nabud_version);
	rv = rv && atom_list_append_done(reply_list);

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

struct connection_req_context {
	const char	*name;
	union {
		struct image_channel *chan;
		char *selected_file;
	};
	uint32_t	op;
	bool		found;
};

static bool
control_req_connection_cb(struct nabu_connection *conn, void *v)
{
	struct connection_req_context *ctx = v;

	if (strcmp(conn_name(conn), ctx->name) != 0) {
		return true;		/* keep enumerating */
	}
	ctx->found = true;

	switch (ctx->op) {
	case NABUCTL_REQ_CONN_CANCEL:
		conn_cancel(conn);
		break;

	case NABUCTL_REQ_CONN_CHANGE_CHANNEL:
		conn_set_channel(conn, ctx->chan);
		break;

	case NABUCTL_REQ_CONN_SELECT_FILE:
		conn_set_selected_file(conn, ctx->selected_file);
		break;

	default:
		break;
	}
	return false;			/* stop enumerating */
}

static bool
conntrol_req_connection_process(struct connection_req_context *ctx,
    struct atom_list *reply_list)
{
	bool rv;

	conn_enumerate(control_req_connection_cb, ctx);

	if (ctx->found) {
		rv = atom_list_append_done(reply_list);
	} else {
		rv = atom_list_append_error(reply_list);
	}
	return rv;
}

/*
 * control_req_connection_cancel --
 *	Handle a CONN CANCEL request.
 */
static bool
control_req_connection_cancel(struct atom *req, struct atom_list *reply_list)
{
	struct connection_req_context ctx = {
		.name = atom_dataref(req),
		.op = NABUCTL_REQ_CONN_CANCEL,
	};

	return conntrol_req_connection_process(&ctx, reply_list);
}

/*
 * control_req_connection_change_chanel --
 *	Handle a CONN CHANGE CHANNEL request.
 */
static bool
control_req_connection_change_channel(struct conn_io *conn, struct atom *req,
    struct atom_list *req_list, struct atom_list *reply_list)
{
	struct atom *number_atom;
	struct connection_req_context ctx = {
		.name = atom_dataref(req),
		.op = NABUCTL_REQ_CONN_CHANGE_CHANNEL,
	};

	number_atom = atom_list_next(req_list, req);
	if (number_atom == NULL ||
	    atom_data_type(number_atom) != NABUCTL_TYPE_NUMBER) {
 bad:
		return atom_list_append_error(reply_list);
	}

	uint64_t val = atom_number_value(number_atom);
	if (val == 0) {
		ctx.chan = NULL;
	} else if (val > 255 ||
		   (ctx.chan =
		    image_channel_lookup((unsigned int)val)) == NULL) {
		goto bad;
	}

	return conntrol_req_connection_process(&ctx, reply_list);
}

/*
 * control_req_connection_select_file --
 *	Handle a CONN SELECT FILE request.
 */
static bool
control_req_connection_select_file(struct conn_io *conn, struct atom *req,
    struct atom_list *req_list, struct atom_list *reply_list)
{
	struct atom *file_atom;
	struct connection_req_context ctx = {
		.name = atom_dataref(req),
		.op = NABUCTL_REQ_CONN_SELECT_FILE,
	};
	bool rv;

	file_atom = atom_list_next(req_list, req);
	if (file_atom == NULL ||
	    (atom_data_type(file_atom) != NABUCTL_TYPE_STRING)) {
		return atom_list_append_error(reply_list);
	}

	ctx.selected_file = atom_consume(file_atom);
	rv = conntrol_req_connection_process(&ctx, reply_list);
	if (! ctx.found) {
		free(ctx.selected_file);
	}
	return rv;
}

/*
 * control_req_channel_clear_cache --
 *	Handle a CHAN CLEAR CACHE request.
 */
static bool
control_req_channel_clear_cache(struct atom *req, struct atom_list *reply_list)
{
	uint64_t val = atom_number_value(req);
	struct image_channel *chan = image_channel_lookup((unsigned int)val);
	if (chan != NULL) {
		image_cache_clear(chan);
		return atom_list_append_done(reply_list);
	}
	return atom_list_append_error(reply_list);
}

/*
 * control_req_channel_fetch_listing --
 *	Handle a CHAN FETCH LISTING request.
 */
static bool
control_req_channel_fetch_listing(struct atom *req,
    struct atom_list *reply_list)
{
	uint64_t val = atom_number_value(req);
	struct image_channel *chan = image_channel_lookup((unsigned int)val);
	if (chan == NULL) {
		return atom_list_append_error(reply_list);
	}

	bool rv = true;
	size_t datalen;
	char *data = image_channel_copy_listing(chan, &datalen);
	if (data != NULL) {
		rv = atom_list_append(reply_list, NABUCTL_TYPE_BLOB,
		    data, datalen);
	}
	return rv && atom_list_append_done(reply_list);
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

		if (atom_list_count(&req_list) == 0) {
			log_error("[%s] Empty request atom list??",
			    conn_io_name(conn));
			continue;
		}

		req = atom_list_next(&req_list, NULL);
		assert(req != NULL);

		switch (atom_tag(req)) {
		case NABUCTL_REQ_HELLO:
			log_debug("[%s] Got NABUCTL_REQ_HELLO.",
			    conn_io_name(conn));
			ok = control_req_hello(conn, req,
			    &req_list, &reply_list);
			break;

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

		case NABUCTL_REQ_CONN_CANCEL:
			log_debug("[%s] Got NABUCTL_REQ_CONN_CANCEL.",
			    conn_io_name(conn));
			ok = control_req_connection_cancel(req, &reply_list);
			break;

		case NABUCTL_REQ_CONN_CHANGE_CHANNEL:
			log_debug("[%s] Got NABUCTL_REQ_CONN_CHANGE_CHANNEL.",
			    conn_io_name(conn));
			ok = control_req_connection_change_channel(conn,
			    req, &req_list, &reply_list);
			break;

		case NABUCTL_REQ_CONN_SELECT_FILE:
			log_debug("[%s] Got NABUCTL_REQ_CONN_SELECT_FILE.",
			    conn_io_name(conn));
			ok = control_req_connection_select_file(conn,
			    req, &req_list, &reply_list);
			break;

		case NABUCTL_REQ_CHAN_CLEAR_CACHE:
			log_debug("[%s] Got NABUCTL_REQ_CHAN_CLEAR_CACHE.",
			    conn_io_name(conn));
			ok = control_req_channel_clear_cache(req, &reply_list);
			break;

		case NABUCTL_REQ_CHAN_FETCH_LISTING:
			log_debug("[%s] Got NABUCTL_REQ_CHAN_FETCH_LISTING.",
			    conn_io_name(conn));
			ok = control_req_channel_fetch_listing(req,
			    &reply_list);
			break;

		default:
			log_error("[%s] Unknown request atom: 0x%08x",
			    conn_io_name(conn), atom_tag(req));
			ok = atom_list_append_error(&reply_list);
			break;
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
 * control_peer_name --
 *	Figure out the control connection peer name, if we can.
 */
static char *
control_peer_name(struct conn_io *conn, int sock)
{
#if defined(LOCAL_PEEREID)
	/*
	 * NetBSD-like LOCAL_PEEREID.
	 */
	struct unpcbid cred;
	socklen_t len = sizeof(cred);
	char *name;

	/*
	 * NetBSD hasn't always had an SOL_LOCAL define, but prior to
	 * it existing, programs simply used the value 0.
	 */
#ifndef SOL_LOCAL
#define	SOL_LOCAL	0
#endif

	if (getsockopt(sock, SOL_LOCAL, LOCAL_PEEREID, &cred, &len) == 0) {
		if (asprintf(&name, "pid-%d", (int)cred.unp_pid) >= 0) {
			return name;
		}
	}
#elif defined(LOCAL_PEERPID)
	/*
	 * macOS-like LOCAL_PEERPID
	 */
	pid_t pid;
	socklen_t len = sizeof(pid);
	char *name;

	if (getsockopt(sock, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0) {
		if (asprintf(&name, "pid-%d", (int)pid) >= 0) {
			return name;
		}
	}
#elif defined(LOCAL_PEERCRED) && defined(HAVE_XUCRED_CR_PID)
	/*
	 * FreeBSD-like LOCAL_PEERCRED.
	 */
	struct xucred cred;
	socklen_t len = sizeof(cred);
	char *name;

	if (getsockopt(sock, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) == 0 &&
	    cred.cr_version == XUCRED_VERSION) {
		if (asprintf(&name, "pid-%d", (int)cred.cr_pid) >= 0) {
			return name;
		}
	}
#elif defined(SO_PEERCRED)
	/*
	 * Linux-like SO_PEERCRED.  OpenBSD also has this, but uses
	 * a different type to return the data.
	 */
#ifdef HAVE_STRUCT_SOCKPEERCRED
	struct sockpeercred cred;
#else
	struct ucred cred;
#endif
	socklen_t len = sizeof(cred);
	char *name;

	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
		if (asprintf(&name, "pid-%d", (int)cred.pid) >= 0) {
			return name;
		}
	}
#endif
	return strdup(conn_io_name(conn));
}

static const char *nabuctl_sock_path;

/*
 * control_listen_thread --
 *	Worker thread that accepts new control connections.
 */
static void *
control_listen_thread(void *arg)
{
	struct conn_io *conn = arg;
	struct conn_io *newconn;
	char *name;
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

		name = control_peer_name(conn, sock);

		log_info("[%s] Creating new control connection.",
		    conn_io_name(conn));

		newconn = calloc(1, sizeof(*newconn));
		if (newconn == NULL) {
			log_error("Unable to allocate new connection.");
			close(sock);
			continue;
		}
		if (! conn_io_init(newconn, name, sock)) {
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
	(void) unlink(nabuctl_sock_path);

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
	nabuctl_sock_path = path;

	if (strlen(path) > sizeof(sun.sun_path)) {
		log_error("Path to control socket is too long: %s", path);
		return;
	}

	memset(&sun, 0, sizeof(sun));
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));
#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun.sun_len = SUN_LEN(&sun);
#endif
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
			/*
			 * Make sure a connection can be established
			 * by anyone who is a member of the group with
			 * our effective GID.
			 */
			log_debug("Changing group on %s to %d.",
			    path, (int)getegid());
			if (chown(path, (uid_t)-1, getegid()) == 0) {
				struct stat sb;
				if (stat(path, &sb) == 0) {
					sb.st_mode |= S_IWGRP;
					log_debug("Cnanging mode on %s to "
					    "0%03o", path, sb.st_mode & 0777);
					if (chmod(path, sb.st_mode) < 0) {
						log_error("chmod(%s, 0%03o): "
						    "%s", path, sb.st_mode,
						    strerror(errno));
					}
				} else {
					log_error("stat(%s): %s", path,
					    strerror(errno));
				}
			} else {
				log_error("chown(%s, -1, %d): %s",
				    path, (int)getegid(), strerror(errno));
			}
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
	(void) unlink(path);
	if (sock >= 0) {
		close(sock);
	}
	if (conn != NULL) {
		free(conn);
	}
}
