/*-
 * Copyright (c) 2022, 2023 Jason R. Thorpe.
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
 * Support for the NabuRetroNet protocol extensions.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#define	NABU_PROTO_INLINES

#include "libnabud/fileio.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"
#include "libnabud/nabu_proto.h"
#include "libnabud/retronet_proto.h"
#include "libnabud/nbsd_queue.h"

#include "conn.h"
#include "retronet.h"
#include "stext.h"

union retronet_request {
	struct rn_file_open_req		file_open;
	struct rn_fh_size_req		fh_size;
	struct rn_fh_read_req		fh_read;
	struct rn_fh_close_req		fh_close;
	struct rn_file_size_req		file_size;
	struct rn_fh_append_req		fh_append;
	struct rn_fh_insert_req		fh_insert;
	struct rn_fh_delete_range_req	fh_delete_range;
	struct rn_fh_replace_req	fh_replace;
	struct rn_fh_file_delete_req	file_delete;
	struct rn_file_copy_req		file_copy;
	struct rn_file_move_req		file_move;
	struct rn_fh_truncate_req	fh_truncate;
	struct rn_file_list_req		file_list;
	struct rn_file_list_item_req	file_list_item;
	struct rn_file_details_req	file_details;
	struct rn_fh_details_req	fh_details;
	struct rn_fh_readseq_req	fh_readseq;
	struct rn_fh_seek_req		fh_seek;
};

union retronet_reply {
	struct rn_file_open_repl	file_open;
	struct rn_fh_size_repl		fh_size;
	struct rn_fh_read_repl		fh_read;
	struct rn_file_size_repl	file_size;
	struct rn_file_list_repl	file_list;
	struct rn_file_details		file_list_item;
	struct rn_file_details		file_details;
	struct rn_file_details		fh_details;
	struct rn_fh_readseq_repl	fh_readseq;
	struct rn_fh_seek_repl		fh_seek;
};

struct retronet_context {
	struct stext_context stext;

	union {
		union retronet_request request;
		union retronet_reply reply;
	};
};

/*****************************************************************************
 * Request handling
 *****************************************************************************/

static void
rn_fileio_attrs_to_file_details(const char *location,
    const struct fileio_attrs *a, struct rn_file_details *d)
{
	struct tm tm_store, *tm;
	uint32_t size;

	memset(d, 0, sizeof(*d));

	if (a != NULL) {
		/*
		 * For now, we're going to assume that the time fields in the
		 * FileDetails map 1:1 to POSIX "struct tm" fields.
		 *
		 * Note that POSIX tm_year and tm_mon is actually:
		 *
		 *	year - 1900
		 *	month of year (0 - 11)
		 *
		 * ...and NABULIB is expecting just raw values.
		 */
		tm = localtime_r(&a->btime, &tm_store);
		nabu_set_uint16(d->c_year, tm->tm_year + 1900);
		d->c_month  = tm->tm_mon + 1;
		d->c_day    = tm->tm_mday;
		d->c_hour   = tm->tm_hour;
		d->c_minute = tm->tm_min;
		d->c_second = tm->tm_sec;

		tm = localtime_r(&a->mtime, &tm_store);
		nabu_set_uint16(d->m_year, tm->tm_year + 1900);
		d->m_month  = tm->tm_mon + 1;
		d->m_day    = tm->tm_mday;
		d->m_hour   = tm->tm_hour;
		d->m_minute = tm->tm_min;
		d->m_second = tm->tm_sec;

		if (a->is_directory) {
			size = NR_ISDIR;
		} else {
			if (a->size > UINT32_MAX) {
				size = UINT32_MAX;
			} else {
				size = (uint32_t)a->size;
			}
		}
	} else {
		/* NULL attrs == file does not exist. */
		size = NR_NOENT;
	}
	nabu_set_uint32(d->file_size, size);

	const char *fname = strrchr(location, '/');
	if (fname == NULL) {
		fname = location;
	}
	size_t fnamelen = strlen(fname);
	if (fnamelen > sizeof(d->name)) {
		fnamelen = sizeof(d->name);
	}
	d->name_length = (uint8_t)fnamelen;
	memcpy(d->name, fname, fnamelen);
}

/*
 * rn_req_file_open --
 *	Handle the FILE-OPEN request.
 */
static void
rn_req_file_open(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio_attrs attrs;
	struct stext_file *f;
	int error;
	uint16_t flags;
	uint8_t reqslot;

	/* First we have to get the file name length. */
	if (! conn_recv_byte(conn, &ctx->request.file_open.fileNameLen)) {
		log_error("[%s] Failed to receive fileNameLen.",
		    conn_name(conn));
		return;
	}

	/* Now we can receive the rest of the payload. */
	if (! conn_recv(conn, ctx->request.file_open.fileName,
			ctx->request.file_open.fileNameLen + 3)) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	uint8_t *cp = &ctx->request.file_open.fileName[
	    ctx->request.file_open.fileNameLen];

	/* Extract the flags and requested slot. */
	flags = nabu_get_uint16(cp);
	reqslot = cp[2];

	/* XXX consume flags */
	(void)flags;

	/* Now NUL-terminate the name. */
	*cp = '\0';

	error = stext_file_open(&ctx->stext,
	    (const char *)ctx->request.file_open.fileName,
	    reqslot, &attrs, &f);
	if (error == EBUSY) {
		/*
		 * The RetroNet API says to treat a busy requested
		 * slot as "ok, then just allocate one.".  &shrug;
		 */
		error = stext_file_open(&ctx->stext,
		    (const char *)ctx->request.file_open.fileName,
		    0xff, &attrs, &f);
	}

	/*
	 * The RetroNet API has no way to indicate an error, so we
	 * return a dummy handle of 0xff in that case check for it
	 * later when I/O is requested.
	 */
	if (error != 0) {
		ctx->reply.file_open.fileHandle = 0xff;
	} else {
		ctx->reply.file_open.fileHandle = stext_file_slot(f);
	}

	conn_send(conn, &ctx->reply.file_open, sizeof(ctx->reply.file_open));
}

/*
 * rn_req_fh_size --
 *	Handle the FH-SIZE request.
 */
static void
rn_req_fh_size(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio_attrs attrs;
	struct stext_file *f;
	int32_t size;
	int error;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_size,
			sizeof(ctx->request.fh_size))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_read.fileHandle);
	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_read.fileHandle);
		size = -1;
	} else {
		error = stext_file_getattr(f, &attrs);
		if (error != 0) {
			log_error("[%s] stext_file_getattr() failed: %s",
			    conn_name(conn), strerror(error));
			size = -1;
		} else {
			if (attrs.size > INT32_MAX) {
				/* Saturate to INT32_MAX. */
				size = INT32_MAX;
			} else {
				size = (int32_t)attrs.size;
			}
		}
	}
	nabu_set_uint32(ctx->reply.fh_size.fileSize, (uint32_t)size);
	conn_send(conn, &ctx->reply.fh_size, sizeof(ctx->reply.fh_size));
}

/*
 * rn_req_fh_read --
 *	Handle the FH-READ request.
 */
static void
rn_req_fh_read(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_read,
			sizeof(ctx->request.fh_read))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_read.fileHandle);

	uint32_t offset = nabu_get_uint32(ctx->request.fh_read.offset);
	uint16_t length = nabu_get_uint16(ctx->request.fh_read.length);

	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_read.fileHandle);
		length = 0;
	} else {
		log_debug("[%s] slot %u offset %u length %u",
		    conn_name(conn), ctx->request.fh_read.fileHandle,
		    offset, length);

		int error = stext_file_pread(f, ctx->reply.fh_read.data,
		    offset, &length);
		if (error != 0) {
			length = 0;
		}
	}
	nabu_set_uint16(ctx->reply.fh_read.returnLength, length);
	conn_send(conn, &ctx->reply.fh_read, length + 2);
}

/*
 * rn_req_fh_close --
 *	Handle the FH-CLOSE request.
 */
static void
rn_req_fh_close(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_close,
			sizeof(ctx->request.fh_close))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_close.fileHandle);
	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_close.fileHandle);
		return;
	}
	log_debug("[%s] Closing file at slot %u.", conn_name(conn),
	    stext_file_slot(f));
	stext_file_close(f);
}

/*
 * rn_req_file_size --
 *	Handle the FILE-SIZE request.
 */
static void
rn_req_file_size(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio *f;
	struct fileio_attrs attrs;
	int32_t size;

	/* First we have to get the file name length. */
	if (! conn_recv_byte(conn, &ctx->request.file_size.fileNameLen)) {
		log_error("[%s] Failed to receive fileNameLen.",
		    conn_name(conn));
		return;
	}

	/* Now we can receive the rest of the payload. */
	if (! conn_recv(conn, ctx->request.file_size.fileName,
			ctx->request.file_size.fileNameLen)) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	/* NUL-terminate the name. */
	ctx->request.file_size.fileName[
	    ctx->request.file_size.fileNameLen] = '\0';

	/*
	 * Open the file so we can get the size.  Yes, open.
	 * This is necessary for remote files on the other
	 * end of an HTTP connection, for example.
	 */
	f = fileio_open((const char *)ctx->request.file_size.fileName,
	    FILEIO_O_RDONLY | FILEIO_O_LOCAL_ROOT, conn->file_root,
	    &attrs);
	if (f != NULL) {
		if (attrs.size > INT32_MAX) {
			/* Saturate to INT32_MAX. */
			size = INT32_MAX;
		} else {
			size = (int32_t)attrs.size;
		}
		fileio_close(f);
	} else {
		size = -1;
	}
	nabu_set_uint32(ctx->reply.file_size.fileSize, (uint32_t)size);
	conn_send(conn, &ctx->reply.file_size, sizeof(ctx->reply.file_size));
}

/*
 * rn_req_fh_append --
 *	Handle the FH-APPEND request.
 */
static void
rn_req_fh_append(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio_attrs attrs;
	struct stext_file *f;
	uint32_t size;
	int error;

	/*
	 * Get the first few bytes of the request so we know how
	 * much data we'll need to read.
	 */
	if (! conn_recv(conn, &ctx->request.fh_append,
			offsetof(struct rn_fh_append_req, data))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_append.fileHandle);

	uint16_t length = nabu_get_uint16(ctx->request.fh_append.length);

	/* And now receive the data payload. */
	if (! conn_recv(conn, ctx->request.fh_append.data, length)) {
		log_error("[%s] Failed to receive data.",
		    conn_name(conn));
		return;
	}

	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(conn), ctx->request.fh_append.fileHandle);
		return;
	}

	error = stext_file_getattr(f, &attrs);
	if (error != 0) {
		log_error("[%s] stext_file_getattr() failed: %s",
		    conn_name(conn), strerror(error));
		return;
	} else {
		if (attrs.size >= UINT32_MAX) {
			log_error("[%s] file is already too large (%lld).",
			    conn_name(conn), (long long)attrs.size);
			return;
		} else {
			size = (uint32_t)attrs.size;
		}
	}

	error = stext_file_pwrite(f, ctx->request.fh_append.data,
	    size, length);
	if (error != 0) {
		log_error("[%s] stext_file_pwrite() failed: %s",
		    conn_name(conn), strerror(error));
	}
}

/*
 * rn_req_fh_insert --
 *	Handle the FH-INSERT request.
 */
static void
rn_req_fh_insert(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/*
	 * Get the first few bytes of the request so we know how
	 * much data we'll need to read.
	 */
	if (! conn_recv(conn, &ctx->request.fh_insert,
			offsetof(struct rn_fh_insert_req, data))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_insert.fileHandle);

	uint32_t offset = nabu_get_uint32(ctx->request.fh_insert.offset);
	uint16_t length = nabu_get_uint16(ctx->request.fh_insert.length);

	/* And now receive the data payload. */
	if (! conn_recv(conn, ctx->request.fh_insert.data, length)) {
		log_error("[%s] Failed to receive data.",
		    conn_name(conn));
		return;
	}

	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(conn), ctx->request.fh_replace.fileHandle);
		return;
	}

	/* XXX implement FH-INSERT */
	(void)offset;
}

/*
 * rn_req_fh_delete_range --
 *	Handle the FH-DELETE-RANGE request.
 */
static void
rn_req_fh_delete_range(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_delete_range,
			sizeof(ctx->request.fh_delete_range))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext,
	    ctx->request.fh_delete_range.fileHandle);

	uint32_t offset = nabu_get_uint32(ctx->request.fh_delete_range.offset);
	uint16_t length =
	    nabu_get_uint16(ctx->request.fh_delete_range.deleteLen);

	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(conn), ctx->request.fh_replace.fileHandle);
		return;
	}

	/* XXX implement FH-DELETE-RANGE */
	(void)offset;
	(void)length;
}

/*
 * rn_req_fh_replace --
 *	Handle the FH-REPLACE request.  Despite it's odd-ball name,
 *	this is basically just pwrite(2).
 */
static void
rn_req_fh_replace(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/*
	 * Get the first few bytes of the request so we know how
	 * much data we'll need to read.
	 */
	if (! conn_recv(conn, &ctx->request.fh_replace,
			offsetof(struct rn_fh_replace_req, data))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_replace.fileHandle);

	uint32_t offset = nabu_get_uint32(ctx->request.fh_replace.offset);
	uint16_t length = nabu_get_uint16(ctx->request.fh_replace.length);

	/* And now receive the data payload. */
	if (! conn_recv(conn, ctx->request.fh_replace.data, length)) {
		log_error("[%s] Failed to receive data.",
		    conn_name(conn));
		return;
	}

	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(conn), ctx->request.fh_replace.fileHandle);
		return;
	}

	int error = stext_file_pwrite(f, ctx->request.fh_replace.data,
	    offset, length);
	if (error != 0) {
		log_error("[%s] stext_file_pwrite() failed: %s",
		    conn_name(conn), strerror(error));
	}
}

/*
 * rn_req_file_delete --
 *	Handle the FILE-DELETE request.
 */
static void
rn_req_file_delete(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;

	/* First we have to get the file name length. */
	if (! conn_recv_byte(conn, &ctx->request.file_delete.fileNameLen)) {
		log_error("[%s] Failed to receive fileNameLen.",
		    conn_name(conn));
		return;
	}

	/* Now we can receive the rest of the payload. */
	if (! conn_recv(conn, ctx->request.file_delete.fileName,
			ctx->request.file_size.fileNameLen)) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	/* NUL-terminate the name. */
	ctx->request.file_delete.fileName[
	    ctx->request.file_delete.fileNameLen] = '\0';

	/* XXX implement FILE-DELETE */
}

static bool
rn_file_copy_mode_getargs(struct retronet_context *ctx,
    const char **src_fnamep, const char **dst_fnamep, uint8_t *flagsp)
{
	struct nabu_connection *conn = ctx->stext.conn;
	char *src_fname = NULL, *dst_fname = NULL;
	uint8_t src_fname_len, dst_fname_len, flags;
	uint8_t *cp;

	/*
	 * This request "structure" is a friggin' mess.  We just have
	 * to treat it like a free-form blob because it contains variable-
	 * length fields in the middle.
	 */
	cp = ctx->request.file_copy.ugh;

	/* Source name length. */
	if (! conn_recv_byte(conn, cp)) {
		log_error("[%s] Failed to receive srcFileNameLen.",
		    conn_name(conn));
		return false;
	}
	src_fname_len = *cp;
	cp++;

	/* Source name. */
	if (! conn_recv(conn, cp, src_fname_len)) {
		log_error("[%s] Failed to receive srcFileName.",
		    conn_name(conn));
		return false;
	}
	src_fname = (char *)cp;
	cp += src_fname_len;

	/* Destination name length. */
	if (! conn_recv_byte(conn, cp)) {
		log_error("[%s] Failed to receive dstFileNameLen.",
		    conn_name(conn));
		return false;
	}
	dst_fname_len = *cp;
	cp++;

	/* Destination name. */
	if (! conn_recv(conn, cp, dst_fname_len)) {
		log_error("[%s] Failed to receive dstFileName.",
		    conn_name(conn));
		return false;
	}
	dst_fname = (char *)cp;
	cp += dst_fname_len;

	/* ...and the flags. */
	if (! conn_recv_byte(conn, cp)) {
		log_error("[%s] Failed to receive copyFlags.",
		    conn_name(conn));
		return false;
	}
	flags = *cp;
	cp++;

	/*
	 * All of the other info after the file names has now been
	 * saved off so we can NUL-terminate the names.
	 */
	src_fname[src_fname_len] = '\0';
	dst_fname[dst_fname_len] = '\0';

	*src_fnamep = src_fname;
	*dst_fnamep = dst_fname;
	*flagsp = flags;

	return true;
}

/*
 * rn_req_file_copy --
 *	Handle the FILE-COPY request.
 */
static void
rn_req_file_copy(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	const char *src_fname, *dst_fname;
	uint8_t flags;

	/* FILE-COPY and FILE-MOVE have the same args "structure". */
	if (! rn_file_copy_mode_getargs(ctx, &src_fname, &dst_fname, &flags)) {
		log_error("[%s] Failed to get arguments.",
		    conn_name(conn));
		return;
	}

	/* XXX implement FILE-COPY */
}

/*
 * rn_req_file_move --
 *	Handle the FILE-MOVE request.
 */
static void
rn_req_file_move(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	const char *src_fname, *dst_fname;
	uint8_t flags;

	/* FILE-COPY and FILE-MOVE have the same args "structure". */
	if (! rn_file_copy_mode_getargs(ctx, &src_fname, &dst_fname, &flags)) {
		log_error("[%s] Failed to get arguments.",
		    conn_name(conn));
		return;
	}

	/* XXX implement FILE-MOVE */
}

/*
 * rn_req_fh_truncate --
 *	Handle the FH-EMPTY-FILE (which is "truncate to 0") request.
 */
static void
rn_req_fh_truncate(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;
	int error;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_truncate,
			sizeof(ctx->request.fh_truncate))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_truncate.fileHandle);
	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_truncate.fileHandle);
		return;
	}

	error = stext_file_truncate(f, 0);
	if (error != 0) {
		log_error("[%s] stext_file_truncate() failed: %s",
		    conn_name(conn), strerror(error));
	}
}

/*
 * rn_req_file_list --
 *	Handle the FILE-LIST request.
 */
static void
rn_req_file_list(struct retronet_context *ctx)
{
}

/*
 * rn_req_file_list_item --
 *	Handle the FILE-LIST-ITEM request.
 */
static void
rn_req_file_list_item(struct retronet_context *ctx)
{
}

/*
 * rn_req_file_details --
 *	Handle the FILE-DETAILS request.
 */
static void
rn_req_file_details(struct retronet_context *ctx)
{
}

/*
 * rn_req_fh_details --
 *	Handle the FH-DETAILS request.
 */
static void
rn_req_fh_details(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio_attrs attrs, *ap = &attrs;
	struct stext_file *f;
	int error;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_truncate,
			sizeof(ctx->request.fh_truncate))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_truncate.fileHandle);
	if (f == NULL) {
		log_debug("[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_truncate.fileHandle);
		return;
	}

	error = stext_file_getattr(f, ap);
	if (error != 0) {
		log_error("[%s] stext_file_getattr() failed: %s",
		    conn_name(conn), strerror(error));
		ap = NULL;
	}
	rn_fileio_attrs_to_file_details(stext_file_location(f),
	    ap, &ctx->reply.fh_details);
	conn_send(conn, &ctx->reply.fh_details, sizeof(ctx->reply.fh_details));
}

/*
 * rn_req_fh_readseq --
 *	Handle the FH-READSEQ request.
 */
static void
rn_req_fh_readseq(struct retronet_context *ctx)
{
}

/*
 * rn_req_fh_seek --
 *	Handle the FH-SEEK request.
 */
static void
rn_req_fh_seek(struct retronet_context *ctx)
{
}

#define	HANDLER_INDEX(v)	((v) - NABU_MSG_RN_FIRST)
#define	HANDLER_ENTRY(v, n)						\
	[HANDLER_INDEX(v)] = {						\
		.handler    = rn_req_ ## n ,				\
		.debug_desc = #v ,					\
	}

static const struct {
	void		(*handler)(struct retronet_context *);
	const char	*debug_desc;
} retronet_request_types[] = {
	HANDLER_ENTRY(NABU_MSG_RN_FILE_OPEN,       file_open),
	HANDLER_ENTRY(NABU_MSG_RN_FH_SIZE,         fh_size),
	HANDLER_ENTRY(NABU_MSG_RN_FH_READ,         fh_read),
	HANDLER_ENTRY(NABU_MSG_RN_FH_CLOSE,        fh_close),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_SIZE,       file_size),
	HANDLER_ENTRY(NABU_MSG_RN_FH_APPEND,       fh_append),
	HANDLER_ENTRY(NABU_MSG_RN_FH_INSERT,       fh_insert),
	HANDLER_ENTRY(NABU_MSG_RN_FH_DELETE_RANGE, fh_delete_range),
	HANDLER_ENTRY(NABU_MSG_RN_FH_REPLACE,      fh_replace),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_DELETE,     file_delete),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_COPY,       file_copy),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_MOVE,       file_move),
	HANDLER_ENTRY(NABU_MSG_RN_FH_TRUNCATE,     fh_truncate),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_LIST,       file_list),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_LIST_ITEM,  file_list_item),
	HANDLER_ENTRY(NABU_MSG_RN_FILE_DETAILS,    file_details),
	HANDLER_ENTRY(NABU_MSG_RN_FH_DETAILS,      fh_details),
	HANDLER_ENTRY(NABU_MSG_RN_FH_READSEQ,      fh_readseq),
	HANDLER_ENTRY(NABU_MSG_RN_FH_SEEK,         fh_seek),
};
static const unsigned int retronet_request_type_count =
    sizeof(retronet_request_types) / sizeof(retronet_request_types[0]);

#undef HANDLER_ENTRY

/*
 * retronet_context_alloc --
 *	Allocate a RetroNet context for the specified connection.
 */
static struct retronet_context *
retronet_context_alloc(struct nabu_connection *conn)
{
	struct retronet_context *ctx = calloc(1, sizeof(*ctx));
	if (ctx != NULL) {
		stext_context_init(&ctx->stext, conn);
		conn->retronet = ctx;
	}
	return ctx;
}

/*
 * retronet_context_free --
 *	Free a RetroNet context and all associated resources.
 */
static void
retronet_context_free(struct retronet_context *ctx)
{
	assert(ctx->stext.conn->retronet == ctx);
	ctx->stext.conn->retronet = NULL;
	stext_context_fini(&ctx->stext);
	free(ctx);
}

/*
 * retronet_request --
 *	Handle a RetroNet request.
 */
bool
retronet_request(struct nabu_connection *conn, uint8_t msg)
{
	struct retronet_context *ctx;
	uint8_t idx = HANDLER_INDEX(msg);

	if (! conn->retronet_enabled) {
		log_debug("[%s] RetroNet is not enabled.",
		    conn_name(conn));
		return false;
	}

	if (idx > retronet_request_type_count ||
	    retronet_request_types[idx].handler == NULL) {
		log_error("[%s] Unknown RetroNet request type 0x%02x.",
		    conn_name(conn), msg);
		return true;
	}

	if ((ctx = conn->retronet) == NULL) {
		/*
		 * First RetroNet call -- allocate a context for
		 * this connection.
		 */
		ctx = retronet_context_alloc(conn);
		if (ctx == NULL) {
			log_error("[%s] Unable to allocate RetroNet context.",
			    conn_name(conn));
			return true;
		}
	}

	log_debug("[%s] Got %s.", conn_name(conn),
	    retronet_request_types[idx].debug_desc);
	(*retronet_request_types[idx].handler)(ctx);
	return true;
}

/*
 * retronet_conn_fini --
 *	Tear down any lingering RetroNet state for a connection.
 */
void
retronet_conn_fini(struct nabu_connection *conn)
{
	if (conn->retronet != NULL) {
		retronet_context_free(conn->retronet);
	}
}
