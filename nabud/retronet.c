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
 * Support for NabuRetroNet features / extensions.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "conn.h"
#include "fileio.h"
#include "log.h"
#include "retronet.h"

/*
 * rn_store_blob_free --
 *	Free a blob.
 */
static void
rn_store_blob_free(struct rn_blob *blob)
{
	free(blob->url);
	free(blob->data);
	free(blob);
}

/*
 * rn_store_get_slot --
 *	Get the blob from a blob store slot.
 */
static struct rn_blob *
rn_store_get_slot(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_blob *blob;

	/*
	 * No need to hold the channel mutex or track references -- the
	 * blobs are only ever referenced by the thread that owns the
	 * connection.
	 */
	LIST_FOREACH(blob, &conn->rn_store, link) {
		if (blob->slot == slot) {
			break;
		}
	}
	return blob;
}

/*
 * rn_store_set_slot --
 *	Set the a blob store slot.
 */
static void
rn_store_set_slot(struct nabu_connection *conn, uint8_t slot,
    struct rn_blob *blob)
{
	struct rn_blob *oblob;

	/* See note in rn_store_get_slot(). */

	oblob = rn_store_get_slot(conn, slot);
	if (oblob) {
		LIST_REMOVE(oblob, link);
		rn_store_blob_free(oblob);
	}
	LIST_INSERT_HEAD(&conn->rn_store, blob, link);
}

/*
 * rn_store_clear --
 *	Clear out the blob store.
 */
void
rn_store_clear(struct nabu_connection *conn)
{
	struct rn_blob *blob;

	/* See note in rn_store_get_slot(). */

	while ((blob = LIST_FIRST(&conn->rn_store)) != NULL) {
		LIST_REMOVE(blob, link);
		rn_store_blob_free(blob);
	}
}

/* 
 * rn_store_http_get --
 *	Get the blob at the specified URL and insert it into
 *	the connection's blob store.
 */
bool
rn_store_http_get(struct nabu_connection *conn, char *url, uint8_t slot)
{
	struct rn_blob *blob;
	size_t filesize;
	uint8_t *data;

	/*
	 * Download the file before we do anything.  Note that we
	 * ALWAYS download, even if we already have a blob at the
	 * same URL in this slot, because the content may have
	 * changed.
	 *
	 * Cap the size at NABU_MAXSEGMENTSIZE for now (the
	 * GetDataSize request only has a 16-bit size return).
	 */
	data = fileio_load_from_url(url, NABU_MAXSEGMENTSIZE, &filesize);
	if (data == NULL) {
		/* Error already logged. Clear out existing slot. */
		rn_store_set_slot(conn, slot, NULL);
		free(url);
		return false;
	}

	blob = calloc(1, sizeof(*blob));
	if (blob == NULL) {
		log_error("[%s] Unable to allocate RN blob descriptor "
		    "for slot %u.", conn->name, slot);
		free(data);
		free(url);
	}

	blob->url = url;
	blob->data = data;
	blob->length = filesize;
	blob->slot = slot;

	log_info("[%s] Storing %zu bytes of data from %s in slot %u.",
	    conn->name, filesize, url, slot);

	rn_store_set_slot(conn, slot, blob);
	return true;
}

/*
 * rn_store_get_size --
 *	Get the size of the data at the specified slot.  If there is
 *	no blob stored at that slot, return 0.
 */
size_t
rn_store_get_size(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_blob *blob;

	blob = rn_store_get_slot(conn, slot);
	return blob != NULL ? blob->length : 0;
}

/*
 * rn_store_get_data --
 *	Get the data at the specified offset of the specified slot.
 *	Returns the amount of valid data in *datalenp.
 */
const uint8_t *
rn_store_get_data(struct nabu_connection *conn, uint8_t slot, size_t offset,
    size_t *datalenp)
{
	struct rn_blob *blob;

	blob = rn_store_get_slot(conn, slot);
	if (blob == NULL || offset >= blob->length) {
		*datalenp = 0;
		return NULL;
	}

	*datalenp = blob->length - offset;
	return blob->data + offset;
}
