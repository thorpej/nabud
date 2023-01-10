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
 * Support for sending and receving nabud control message atoms.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "atom.h"
#include "log.h"

/*
 * atom_alloc --
 *	Allocate an atom.
 */
static struct atom *
atom_alloc(size_t len)
{
	struct atom *atom = calloc(1, sizeof(struct atom));
	if (atom != NULL && len != 0) {
		atom->data = calloc(1, len);
		if (atom->data == NULL) {
			free(atom);
			return NULL;
		}
	}
	return atom;
}

/*
 * atom_free --
 *	Free an atom.
 */
static void
atom_free(struct atom *atom)
{
	if (atom->data != NULL) {
		free(atom->data);
	}
	free(atom);
}

/*
 * atom_typedesc --
 *	Return a string describing an atom's data type.
 */
static const char *
atom_typedesc(uint32_t tag)
{
	switch (NABUCTL_TYPE(tag)) {
	case NABUCTL_TYPE_VOID:		return "VOID";
	case NABUCTL_TYPE_STRING:	return "STRING";
	case NABUCTL_TYPE_NUMBER:	return "NUMBER";
	case NABUCTL_TYPE_BLOB:		return "BLOB";
	default:			return "???";
	}
}

/*
 * atom_objdesc --
 *	Return a string describing an atom's object type.
 */
static const char *
atom_objdesc(uint32_t tag)
{
	switch (NABUCTL_OBJ(tag)) {
	case NABUCTL_OBJ_CHANNEL:	return "CHANNEL";
	case NABUCTL_OBJ_CONNECTION:	return "CONNECTION";
	default:			return "???";
	}
}

/*
 * atom_data_type --
 *	Return the data type of an atom.
 */
uint32_t
atom_data_type(struct atom *atom)
{
	return NABUCTL_TYPE(atom->hdr.tag);
}

/*
 * atom_tag --
 *	Return the atom's tag.
 */
uint32_t
atom_tag(struct atom *atom)
{
	return atom->hdr.tag;
}

/*
 * atom_length --
 *	Return the length of an atom.
 */
size_t
atom_length(struct atom *atom)
{
	return atom->hdr.length;
}

/*
 * atom_consume --
 *	Consume the data from the atom.  Caller takes ownership
 *	if the buffer and is responsible for freeing it.
 */
void *
atom_consume(struct atom *atom)
{
	void *rv = atom->data;
	atom->data = NULL;
	return rv;
}

/*
 * atom_send_hdr --
 *	Send the atom header.
 */
static void
atom_send_hdr(struct conn_io *conn, const struct nabuctl_atom_header *hdr)
{
	struct nabuctl_atom_header buf = {
		.tag = htonl(hdr->tag),
		.length = htonl(hdr->length),
	};
	conn_io_send(conn, &buf, sizeof(buf));
}

/*
 * atom_send_error --
 *	Helper to send an ERROR atom.
 */
void
atom_send_error(struct conn_io *conn)
{
	static const struct nabuctl_atom_header buf = {
		.tag = htonl(NABUCTL_ERROR),
	};
	conn_io_send(conn, &buf, sizeof(buf));
}

/*
 * atom_send --
 *	Send an atom.
 */
static void
atom_send(struct conn_io *conn, const struct atom *atom)
{
	atom_send_hdr(conn, &atom->hdr);
	if (atom->hdr.length != 0) {
		assert(atom->data != NULL);
		conn_io_send(conn, atom->data, atom->hdr.length);
	}
}

/*
 * atom_recv --
 *	Receive an atom.
 */
static struct atom *
atom_recv(struct conn_io *conn)
{
	struct nabuctl_atom_header hdr;

	if (! conn_io_recv(conn, &hdr, sizeof(hdr))) {
		if (conn_io_state(conn) == CONN_STATE_EOF) {
			log_info("[%s] Peer disconnected.",
			    conn_io_name(conn));
		} else if (conn_io_state(conn) == CONN_STATE_CANCELLED) {
			log_info("[%s] Received cancellation request.",
			    conn_io_name(conn));
		} else if (conn_io_state(conn) == CONN_STATE_ABORTED) {
			log_error("[%s] Connection aborted.",
			    conn_io_name(conn));
		} else {
			log_error("[%s] Failed to receive atom header.",
			    conn_io_name(conn));
		}
		return NULL;
	}
	hdr.tag = ntohl(hdr.tag);
	hdr.length = ntohl(hdr.length);

	/* Sanity-check the data type vs payload. */
	switch (NABUCTL_TYPE(hdr.tag)) {
	case NABUCTL_TYPE_VOID:
		if (hdr.length != 0) {
			log_error("[%s] %s atom has length %u.",
			    conn_io_name(conn), atom_typedesc(hdr.tag),
			    hdr.length);
			return NULL;
		}
		break;

	case NABUCTL_TYPE_STRING:
	case NABUCTL_TYPE_BLOB:
		/*
		 * Even an empty string has to have a nul.  Also
		 * constrain size to something reasonable.
		 */
		if (hdr.length == 0 || hdr.length > 65536) {
			log_error("[%s] %s atom unreasonable length %u.",
			    conn_io_name(conn), atom_typedesc(hdr.tag),
			    hdr.length);
			return NULL;
		}
		break;

	case NABUCTL_TYPE_NUMBER:
		/* As above, but also constrained length. */
		if (hdr.length == 0 ||
		    hdr.length > sizeof("0xffffffffffffffff")) {
			log_error("[%s] %s atom unreasonable length %u.",
			    conn_io_name(conn), atom_typedesc(hdr.tag),
			    hdr.length);
			return NULL;
		}
		break;

	default:
		log_error("[%s] Unknown atom type 0x%08x length %u.",
		    conn_io_name(conn), NABUCTL_TYPE(hdr.tag),
		    hdr.length);
		return NULL;
	}

	struct atom *atom = atom_alloc(hdr.length);
	if (atom == NULL) {
		log_error("[%s] Unable to allocate %u byte atom.",
		    conn_io_name(conn), hdr.length);
		return NULL;
	}
	atom->hdr = hdr;
	if (atom->hdr.length != 0) {
		if (! conn_io_recv(conn, atom->data, atom->hdr.length)) {
			log_error("[%s] Failed to receive %u byte atom "
			    "data.", conn_io_name(conn), atom->hdr.length);
			atom_free(atom);
			return NULL;
		}
		/*
		 * Strings and numbers must have a nul terminator.
		 */
		if (NABUCTL_TYPE(hdr.tag) == NABUCTL_TYPE_STRING ||
		    NABUCTL_TYPE(hdr.tag) == NABUCTL_TYPE_NUMBER) {
			const uint8_t *cp = atom->data;
			if (cp[hdr.length - 1] != '\0') {
				log_error("[%s] %s atom is not nul-terminated.",
				    conn_io_name(conn), atom_typedesc(hdr.tag));
				atom_free(atom);
				return NULL;
			}
		}
	}
	return atom;
}

/*
 * atom_list_init --
 *	Initialize an atom list.
 */
void
atom_list_init(struct atom_list *list)
{
	TAILQ_INIT(&list->list);
	list->count = 0;
}

/*
 * atom_list_free --
 *	Free all of the atoms on the atom list.
 */
void
atom_list_free(struct atom_list *list)
{
	struct atom *atom, *natom;

	TAILQ_FOREACH_SAFE(atom, &list->list, link, natom) {
		TAILQ_REMOVE(&list->list, atom, link);
		list->count--;
		atom_free(atom);
	}
}

/*
 * atom_list_append --
 *	Append a data atom to the atom list.
 */
bool
atom_list_append(struct atom_list *list, uint32_t tag, const void *vbuf,
    size_t len)
{
	assert(vbuf == NULL || len != 0);
	assert(len == 0 || vbuf != NULL);
	assert(NABUCTL_TYPE(tag) == NABUCTL_TYPE_VOID || len != 0);
	assert(NABUCTL_TYPE(tag) != NABUCTL_TYPE_VOID || len == 0);

	struct atom *atom = atom_alloc(len);
	if (atom != NULL) {
		atom->hdr.tag = tag;
		atom->hdr.length = (uint32_t)len;
		if (vbuf != NULL) {
			memcpy(atom->data, vbuf, len);
		}
		TAILQ_INSERT_TAIL(&list->list, atom, link);
		list->count++;
		return true;
	}
	return false;
}

/*
 * atom_list_append_string --
 *	Convenience wrapper around atom_list_append().
 */
bool
atom_list_append_string(struct atom_list *list, uint32_t tag,
    const char *str)
{
	assert(NABUCTL_TYPE(tag) == NABUCTL_TYPE_STRING);
	return atom_list_append(list, tag, str, strlen(str) + 1);
}

/*
 * atom_list_append_number --
 *	Convenience wrapper around atom_list_append().
 */
bool
atom_list_append_number(struct atom_list *list, uint32_t tag, uint64_t val)
{
	char str[sizeof("0xffffffffffffffff")];

	assert(NABUCTL_TYPE(tag) == NABUCTL_TYPE_NUMBER);
	snprintf(str, sizeof(str), "0x%llx", (unsigned long long)val);
	return atom_list_append_string(list, tag, str);
}

/*
 * atom_list_append_void --
 *	Convenience wrapper around atom_list_append().
 */
bool
atom_list_append_void(struct atom_list *list, uint32_t tag)
{
	assert(NABUCTL_TYPE(tag) == NABUCTL_TYPE_VOID);
	return atom_list_append(list, tag, NULL, 0);
}

/*
 * atom_list_append_done --
 *	Convenience wrapper around atom_list_append().
 */
bool
atom_list_append_done(struct atom_list *list)
{
	return atom_list_append(list, NABUCTL_DONE, NULL, 0);
}

/*
 * atom_list_append_error --
 *	Convenience wrapper around atom_list_append().
 */
bool
atom_list_append_error(struct atom_list *list)
{
	return atom_list_append(list, NABUCTL_ERROR, NULL, 0);
}

/*
 * atom_list_count --
 *	Return the number of atoms in the list.
 */
unsigned int
atom_list_count(struct atom_list *list)
{
	return list->count;
}

/*
 * atom_list_next --
 *	Return the next atom in the list.
 */
struct atom *
atom_list_next(struct atom_list *list, struct atom *atom)
{
	if (atom == NULL) {
		return TAILQ_FIRST(&list->list);
	}
	return TAILQ_NEXT(atom, link);
}

/*
 * atom_list_send --
 *	Send out an atom list.
 */
bool
atom_list_send(struct conn_io *conn, struct atom_list *list)
{
	struct atom *atom;

	TAILQ_FOREACH(atom, &list->list, link) {
		atom_send(conn, atom);
	}
	return conn_io_state(conn) == CONN_STATE_OK;
}

/*
 * atom_list_recv --
 *	Receive an atom list.
 */
bool
atom_list_recv(struct conn_io *conn, struct atom_list *list)
{
	struct atom *atom;
	size_t total_size = 0;
	uint32_t objtype = 0;

	for (;;) {
		atom = atom_recv(conn);
		if (atom == NULL) {
			/* Error already logged. */
			goto bad;
		}
		TAILQ_INSERT_TAIL(&list->list, atom, link);
		list->count++;

		/* Don't let the size run away from us. */
		total_size += atom->hdr.length;
		if (total_size > (128 * 1024)) {
			log_error("[%s] Unreasonable atom list size: %zu",
			    conn_io_name(conn), total_size);
			goto bad;
		}

		switch (atom->hdr.tag) {
		case NABUCTL_DONE:
			if (objtype == 0) {
				log_debug("[%s] Received complete atom list.",
				    conn_io_name(conn));
				return true;
			}
			log_debug("[%s] Finished receiving %s object.",
			    conn_io_name(conn), atom_objdesc(objtype));
			objtype = 0;
			break;

		case NABUCTL_OBJ_CHANNEL:
		case NABUCTL_OBJ_CONNECTION:
			/* We don't support nested objects. */
			if (objtype != 0) {
				log_error("[%s] Received %s object start "
				    "while processing %s object.",
				    conn_io_name(conn),
				    atom_objdesc(atom->hdr.tag),
				    atom_objdesc(objtype));
				goto bad;
			}
			objtype = atom->hdr.tag;
			break;

		default:
			/*
			 * Object field in the tag should match whatever
			 * object type we're currently processing (including
			 * 0).
			 */
			if (NABUCTL_OBJ(atom->hdr.tag) != objtype) {
				log_error("[%s] Object type mismatch: "
				    "tag=0x%08x objtype=0x%08x",
				    conn_io_name(conn),
				    NABUCTL_OBJ(atom->hdr.tag), objtype);
				goto bad;
			}
			break;
		}
	}
 bad:
	atom_list_free(list);
	return false;
}
