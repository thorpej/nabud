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

#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>
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

struct rn_file_list_entry {
	STAILQ_ENTRY(rn_file_list_entry) link;
	unsigned int idx;
	struct rn_file_details details;
};

struct retronet_context {
	struct stext_context stext;
	STAILQ_HEAD(, rn_file_list_entry) file_list;
	unsigned int file_list_count;
	struct rn_file_list_entry *cached_entry;

	union {
		union retronet_request request;
		union retronet_reply reply;
	};
};

		/* note reference to local variable */
#define	COPY_BUFSIZE	sizeof(ctx->reply.fh_read.data)
#define	COPY_BUF	ctx->reply.fh_read.data

/*****************************************************************************
 * Request handling
 *****************************************************************************/

static int
rn_recv_filename(struct nabu_connection *conn, const char *which,
    uint8_t **cursorp, char **fnamep, uint8_t *fnamelenp)
{
	uint8_t *bp = *cursorp;

	/* First we have to get the file name length. */
	if (! conn_recv_byte(conn, bp)) {
		log_error("[%s] Failed to receive %sLen.",
		    conn_name(conn), which);
		return ETIMEDOUT;
	}
	uint8_t len = *bp++;
	log_debug(LOG_SUBSYS_RETRONET,
	    "[%s] name length: %u", conn_name(conn), len);

	/* Now we can receive the file name itself. */
	if (! conn_recv(conn, bp, len)) {
		log_error("[%s] Failed to receive %s.",
		    conn_name(conn), which);
		return ETIMEDOUT;
	}
	*fnamep = (char *)bp;
	*fnamelenp = len;
	*cursorp = bp + len;

	/*
	 * Go ahead and NUL-termiante the name now.  We might have to do
	 * it again later if there are more arguments after the name, but
	 * this is convient for those places that don't.
	 */
	*(bp + len) = '\0';

	if (! fileio_location_is_local((char *)bp, len)) {
		/* Remote locations don't get "normalized". Blech. */
		return 0;
	}

	/*
	 * Normalize the pathname according to the RetroNet rules (ugh):
	 *
	 *	- All file names are mapped to upper-case.  While
	 *	  not explicitly stated, we assume this also means
	 *	  all path components (sans the configured file-root).
	 *
	 *	- Local path delimeters are \ BECAUSE OF COURSE THEY ARE,
	 *	  so we have to map those to /.
	 *
	 * Note that there is no provision for creating directories in
	 * the RetroNet protocol, and nabud restricts file access to a
	 * specific file-root, so the likelihood of actually encountering
	 * anything other than a plan old file name is pretty low.
	 */
	log_debug(LOG_SUBSYS_RETRONET, "[%s] %s before normalization: '%s'",
	    conn_name(conn), which, *fnamep);
	for (char *cp = (char *)bp; cp < (char *)bp + len; cp++) {
		if (*cp == '\\') {
			*cp = '/';
		} else if (islower((unsigned char)*cp)) {
			*cp = toupper((unsigned char)*cp);
		}
	}
	log_debug(LOG_SUBSYS_RETRONET, "[%s] %s after normalization: '%s'",
	    conn_name(conn), which, *fnamep);

	return 0;
}

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
			size = RN_ISDIR;
		} else {
			if (a->size > UINT32_MAX) {
				size = UINT32_MAX;
			} else {
				size = (uint32_t)a->size;
			}
		}
	} else {
		/* NULL attrs == file does not exist. */
		size = RN_NOENT;
	}
	nabu_set_uint32(d->file_size, size);

	const char *fname = strrchr(location, '/');
	if (fname == NULL) {
		fname = location;
	} else {
		fname++;
	}
	size_t fnamelen = strlen(fname);
	if (fnamelen > sizeof(d->name)) {
		fnamelen = sizeof(d->name);
	}
	d->name_length = (uint8_t)fnamelen;
	memcpy(d->name, fname, fnamelen);
}

static int
rn_file_getattr(struct retronet_context *ctx, struct fileio_attrs *attrs)
{
	struct nabu_connection *conn = ctx->stext.conn;
	char *fname;
	uint8_t fnamelen;

	/*
	 * Used for FILE-SIZE and FILE-DETAILS -- they both have the
	 * same request structure.
	 */

	uint8_t *req = &ctx->request.file_size.fileNameLen;
	int error = rn_recv_filename(conn, "fileName", &req, &fname, &fnamelen);
	if (error != 0) {
		/* Error already logged. */
		return error;
	}

	log_debug(LOG_SUBSYS_RETRONET,
	    "[%s] Getting attributes for '%s'.",
	    conn_name(ctx->stext.conn), fname);
	if (! fileio_getattr_location(fname, FILEIO_O_LOCAL_ROOT,
				      conn->file_root, attrs)) {
		log_info("[%s] Get attributes for '%s' failed: %s",
		    conn_name(ctx->stext.conn), fname, strerror(errno));
		return errno;
	}

	return 0;
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
	char *fname;
	uint8_t fnamelen;

	uint8_t *req = &ctx->request.file_size.fileNameLen;
	int error = rn_recv_filename(conn, "fileName", &req, &fname, &fnamelen);
	if (error != 0) {
		/* Error already logged. */
		return;
	}

	/* Receive the rest of the request (3 bytes). */
	if (! conn_recv(conn, req, 3)) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	/* Extract the flags and requested slot. */
	uint16_t flags = nabu_get_uint16(req);
	uint8_t reqslot = req[2];

	/* Have all the args -- we can safely NUL-terminate the name. */
	fname[fnamelen] = '\0';

	int fileio_flags = (flags & RN_FILE_OPEN_RW) ?
	    FILEIO_O_RDWR : FILEIO_O_RDONLY;

	error = stext_file_open(&ctx->stext, fname, reqslot, &attrs,
	    FILEIO_O_CREAT | FILEIO_O_REGULAR | fileio_flags, &f);
	if (error == EBUSY) {
		/*
		 * The RetroNet API says to treat a busy requested
		 * slot as "ok, then just allocate one.".  &shrug;
		 */
		error = stext_file_open(&ctx->stext, fname, 0xff, &attrs,
		    FILEIO_O_CREAT | FILEIO_O_REGULAR | fileio_flags, &f);
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

	f = stext_file_find(&ctx->stext, ctx->request.fh_size.fileHandle);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_size.fileHandle);
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
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_read.fileHandle);
		length = 0;
	} else {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] slot %u offset %u length %u",
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
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_close.fileHandle);
		return;
	}
	log_debug(LOG_SUBSYS_RETRONET,
	    "[%s] Closing file at slot %u.", conn_name(conn),
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
	struct fileio_attrs attrs;
	int32_t size;
	int error;

	error = rn_file_getattr(ctx, &attrs);
	if (error == 0) {
		if (attrs.size > INT32_MAX) {
			/* Saturate to INT32_MAX. */
			size = INT32_MAX;
		} else {
			size = (int32_t)attrs.size;
		}
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
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
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
	uint8_t *buf = NULL;

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
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(conn), ctx->request.fh_replace.fileHandle);
		return;
	}

	/* No work to do if the length to insert is zero. */
	if (length == 0) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] length is zero; no work to do.", conn_name(conn));
		return;
	}

	/*
	 * First, get the current state of the file and figure out
	 * the boundaries of the affected range.
	 */
	struct fileio_attrs attrs;
	int error;

	error = stext_file_getattr(f, &attrs);
	if (error) {
		log_error("[%s] stext_file_getattr() failed: %s",
		    conn_name(conn), strerror(error));
		return;
	}

	/*
	 * If the insertion comes just at the end-of-file or beyond
	 * it, then there is no need to make room for it.
	 */
	if (offset >= attrs.size) {
		goto do_insert;
	}

	/*
	 * Ok, we have to shuffle file data around to make room for
	 * the insertion.  We're going to need a temporary buffer for
	 * this, and we'll have to walk backwards from the end of the
	 * file to the insertion point.
	 */
	buf = malloc(COPY_BUFSIZE);
	if (buf == NULL) {
		log_error("[%s] Unable to allocate temporary buffer.",
		    conn_name(conn));
		return;
	}

	off_t newsize = attrs.size + length; /* new size of the file */
	off_t resid = attrs.size - offset;   /* amount of data to copy */

	if (newsize <= attrs.size || newsize > UINT32_MAX) {
		log_error("[%s] Resulting file is too large.", conn_name(conn));
		return;
	}

	/*
	 * Ok, we've confirmed the new file will fit within our numerical
	 * constraints.
	 */
	uint32_t readoff = (uint32_t)attrs.size;
	uint32_t writeoff = (uint32_t)newsize;
	uint16_t iolen;

	while (resid != 0) {
		iolen = (resid < COPY_BUFSIZE) ? resid : COPY_BUFSIZE;
		readoff -= iolen;
		writeoff -= iolen;

		error = stext_file_pread(f, buf, readoff, &iolen);
		if (error != 0) {
			log_error("[%s] stext_file_pread() failed: %s",
			    conn_name(conn), strerror(error));
			goto out;
		}
		/* Should never encounter EOF here. */
		if (iolen == 0) {
			log_error("[%s] UNEXPECTED END-OF-FILE!!!",
			    conn_name(conn));
			goto out;
		}
		error = stext_file_pwrite(f, buf, writeoff, iolen);
		if (error != 0) {
			log_error("[%s] stext_file_pwrite() failed: %s",
			    conn_name(conn), strerror(error));
			goto out;
		}
		resid -= iolen;
	}

 do_insert:
	error = stext_file_pwrite(f, ctx->request.fh_insert.data,
	    offset, length);
	if (error != 0) {
		log_error("[%s] stext_file_pwrite() failed: %s",
		    conn_name(conn), strerror(error));
	}

 out:
	if (buf != NULL) {
		free(buf);
	}
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
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] No file for slot %u.", conn_name(conn),
		    ctx->request.fh_delete_range.fileHandle);
		return;
	}

	/* No work to do if the length to delete is zero. */
	if (length == 0) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] length is zero; no work to do.", conn_name(conn));
		return;
	}

	/*
	 * First, get the current state of the file and figure out
	 * the boundaries of the deleted range.
	 */
	struct fileio_attrs attrs;
	int error;

	error = stext_file_getattr(f, &attrs);
	if (error) {
		log_error("[%s] stext_file_getattr() failed: %s",
		    conn_name(conn), strerror(error));
		return;
	}

	if (offset >= attrs.size) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Offset %u beyond end-of-file.",
		    conn_name(conn), offset);
		return;
	}

	if (attrs.size - offset <= length) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Deleted range at tail-of-file (%u).",
		    conn_name(conn), offset);
		/*
		 * No need to move any data in this case; we can just
		 * truncate the file to the offset.
		 */
		stext_file_truncate(f, offset);
		return;
	}

	uint32_t newsize = (uint32_t)attrs.size - length;
	uint32_t keepoff = offset + length;
	assert(keepoff > offset);

	/*
	 * Now, we just copy the data after the deleted range
	 * to the start of the deleted range, then truncate
	 * the file to the new size.
	 */
	assert(COPY_BUFSIZE <= UINT16_MAX);
	for (;;) {
		uint16_t iolen = COPY_BUFSIZE;

		error = stext_file_pread(f, COPY_BUF, keepoff, &iolen);
		if (error != 0) {
			log_error("[%s] stext_file_pread() failed: %s",
			    conn_name(conn), strerror(error));
			break;
		}
		if (iolen == 0) {
			/* EOF! */
			break;
		}
		error = stext_file_pwrite(f, COPY_BUF, offset, iolen);
		if (error != 0) {
			log_error("[%s] stext_file_pwrite() failed: %s",
			    conn_name(conn), strerror(error));
			break;
		}
		keepoff += iolen;
		offset += iolen;
	}
	error = stext_file_truncate(f, newsize);
	if (error != 0) {
		log_error("[%s] stext_file_truncate() failed: %s",
		    conn_name(conn), strerror(error));
	}
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
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
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
	char *fname;
	uint8_t fnamelen;

	uint8_t *req = &ctx->request.file_delete.fileNameLen;
	int error = rn_recv_filename(conn, "fileName", &req, &fname, &fnamelen);
	if (error != 0) {
		/* Error already logged. */
		return;
	}

	char *path =
	    fileio_resolve_path(fname, conn->file_root, FILEIO_O_LOCAL_ROOT);
	if (path != NULL) {
		if (unlink(path) < 0) {
			log_info("[%s] unlink(%s) failed: %s",
			    conn_name(conn), path, strerror(errno));
		}
		free(path);
	} else {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to resolve path: %s", conn_name(conn), fname);
	}
}

static bool
rn_file_copy_move_getargs(struct retronet_context *ctx,
    const char **src_fnamep, const char **dst_fnamep, uint8_t *flagsp)
{
	struct nabu_connection *conn = ctx->stext.conn;
	char *src_fname = NULL, *dst_fname = NULL;
	uint8_t src_fname_len, dst_fname_len, flags;
	int error;

	/*
	 * This request "structure" is a friggin' mess.  We just have
	 * to treat it like a free-form blob because it contains variable-
	 * length fields in the middle.
	 */
	uint8_t *req = ctx->request.file_copy.ugh;
	error = rn_recv_filename(conn, "srcFileName", &req,
	    &src_fname, &src_fname_len);
	if (error != 0) {
		/* Error already logged. */
		return false;
	}
	error = rn_recv_filename(conn, "dstFileName", &req,
	    &dst_fname, &dst_fname_len);
	if (error != 0) {
		/* Error already logged. */
		return false;
	}

	/* ...and the flags. */
	if (! conn_recv_byte(conn, req)) {
		log_error("[%s] Failed to receive copyFlags.",
		    conn_name(conn));
		return false;
	}
	flags = *req;

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
	if (! rn_file_copy_move_getargs(ctx, &src_fname, &dst_fname, &flags)) {
		log_error("[%s] Failed to get arguments.",
		    conn_name(conn));
		return;
	}

	/*
	 * We allow the source to be anywhere (local or remote), but
	 * the destination must be local.
	 */
	int dst_oflags = 0;
	if ((flags & RN_FILE_COPY_MOVE_REPLACE) == 0) {
		dst_oflags |= FILEIO_O_EXCL;
	}
	char *dst_path = fileio_resolve_path(dst_fname, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	if (dst_path == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to resolve dst path: %s",
		    conn_name(conn), dst_fname);
		return;
	}

	struct fileio *src_f = NULL, *dst_f = NULL;

	src_f = fileio_open(src_fname,
	    FILEIO_O_RDONLY | FILEIO_O_REGULAR | FILEIO_O_LOCAL_ROOT,
	    conn->file_root, NULL);
	if (src_f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to open src '%s': %s",
		    conn_name(conn), src_fname, strerror(errno));
		goto out;
	}

	/*
	 * No need to specify LOCAL_ROOT for the destination -- we've
	 * already resolved the path.
	 */
	dst_f = fileio_open(dst_path,
	    FILEIO_O_RDWR | FILEIO_O_CREAT | FILEIO_O_REGULAR | dst_oflags,
	    NULL, NULL);
	if (dst_f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to open dst '%s': %s",
		    conn_name(conn), dst_path, strerror(errno));
		goto out;
	}

	ssize_t actual;
	for (;;) {
		actual = fileio_read(src_f, COPY_BUF, COPY_BUFSIZE);
		if (actual < 0) {
			log_error("[%s] fileio_read() failed: %s",
			    conn_name(conn), strerror(errno));
			goto bad;
		}
		if (actual == 0) {
			/* EOF! */
			log_debug(LOG_SUBSYS_RETRONET,
			    "[%s] Copy complete.", conn_name(conn));
			break;
		}
		actual = fileio_write(dst_f, COPY_BUF, actual);
		if (actual < 0) {
			log_error("[%s] fileio_write() failed: %s",
			    conn_name(conn), strerror(errno));
			goto bad;
		}
	}

 out:
	if (src_f != NULL) {
		fileio_close(src_f);
	}
	if (dst_f != NULL) {
		fileio_close(dst_f);
	}
	return;
 bad:
	unlink(dst_path);
	goto out;
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
	if (! rn_file_copy_move_getargs(ctx, &src_fname, &dst_fname, &flags)) {
		log_error("[%s] Failed to get arguments.",
		    conn_name(conn));
		return;
	}

	char *src_path = fileio_resolve_path(src_fname, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	char *dst_path = fileio_resolve_path(dst_fname, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	bool replace = (flags & RN_FILE_COPY_MOVE_REPLACE) != 0;

	if (src_path == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to resolve src path: %s",
		    conn_name(conn), src_fname);
		goto out;
	}
	if (dst_path == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to resolve dst path: %s",
		    conn_name(conn), dst_fname);
		goto out;
	}

	/*
	 * If we haven't been given the REPLACE flag, then ensure
	 * nothing is at the destination path.
	 */
	if (! replace) {
		struct stat sb;

		if (stat(dst_path, &sb) == 0 || errno != ENOENT) {
			log_info("[%s] Not replacing file at '%s'.",
			    conn_name(conn), dst_path);
			goto out;
		}
	}

	if (rename(src_path, dst_path) < 0) {
		/* XXX Who wants to handle EXDEV?  Because I sure don't... */
		log_info("[%s] rename(%s, %s) failed: %s",
		    conn_name(conn), src_path, dst_path, strerror(errno));
	}

 out:
	if (src_path != NULL) {
		free(src_path);
	}
	if (dst_path != NULL) {
		free(dst_path);
	}
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
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] No file for slot %u.", conn_name(ctx->stext.conn),
		    ctx->request.fh_truncate.fileHandle);
		return;
	}

	error = stext_file_truncate(f, 0);
	if (error != 0) {
		log_error("[%s] stext_file_truncate() failed: %s",
		    conn_name(conn), strerror(error));
	}
}

static void
rn_file_list_free(struct retronet_context *ctx)
{
	struct rn_file_list_entry *e;

	while ((e = STAILQ_FIRST(&ctx->file_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&ctx->file_list, link);
		free(e);
	}
	ctx->file_list_count = 0;
	ctx->cached_entry = NULL;
}

/*
 * rn_req_file_list --
 *	Handle the FILE-LIST request.
 */
static void
rn_req_file_list(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	const char *where, *pattern;
	char *path, *cp;
	glob_t g;
	uint8_t flags;

	/* Clear out any previous file list. */
	rn_file_list_free(ctx);

	/*
	 * While the fields aren't interpreted the same way, somewhat
	 * conveniently the "where", "pattern", and "flags" arguments
	 * to FILE-LIST line up exactly with "src", "dst", and "flags"
	 * for FILE-MOVE and FILE-COPY.
	 */
	if (! rn_file_copy_move_getargs(ctx, &where, &pattern, &flags)) {
		log_error("[%s] Failed to get arguments.",
		    conn_name(conn));
		return;
	}

	memset(&g, 0, sizeof(g));

	path = fileio_resolve_path(where, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	if (path == NULL) {
		log_debug(LOG_SUBSYS_RETRONET,
		    "[%s] Unable to resolve path: %s",
		    conn_name(conn), where);
		goto out;
	}
	log_debug(LOG_SUBSYS_RETRONET, "[%s] Resolved path: %s",
	    conn_name(conn), path);

	/*
	 * Get rid of any trailing /'s -- we'll ensure there is
	 * exactly one below.
	 */
	cp = path + strlen(path) - 1;
	while (cp > path && *cp == '/') {
		*cp-- = '\0';
	}

	if (asprintf(&cp, "%s/%s", path, pattern) < 0) {
		log_error("[%s] Unable to allocate memory for glob pattern.",
		    conn_name(conn));
		goto out;
	}
	free(path);
	path = cp;

	log_debug(LOG_SUBSYS_RETRONET, "[%s] Pattern for glob: %s",
	    conn_name(conn), path);

	/*
	 * We've already converted \ to / in the string, so just
	 * disable escapes.
	 */
	int globret = glob(path, GLOB_NOESCAPE, NULL, &g);
	if (globret != 0) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] glob() returned %d.",
		    conn_name(conn), globret);
		goto out;
	}
	log_debug(LOG_SUBSYS_RETRONET, "[%s] glob() returned %zd matches.",
	    conn_name(conn), (size_t)g.gl_pathc);

	for (int i = 0; i < g.gl_pathc; i++) {
		struct fileio_attrs attrs;
		struct rn_file_list_entry *e = calloc(1, sizeof(*e));
		uint8_t check_flag;

		if (e == NULL) {
			log_error("[%s] Failed to allocate file list entry.",
			    conn_name(conn));
			goto out;
		}
		if (! fileio_getattr_location(g.gl_pathv[i], 0, NULL, &attrs)) {
			log_error("[%s] Unable to get attrs for '%s': %s",
			    conn_name(conn), g.gl_pathv[i], strerror(errno));
			free(e);
			continue;
		}
		check_flag = attrs.is_directory ? RN_FILE_LIST_DIRS
						: RN_FILE_LIST_FILES;
		if ((flags & check_flag) == 0) {
			log_debug(LOG_SUBSYS_RETRONET,
			    "[%s] Skipping '%s' due to flags.",
			    conn_name(conn), g.gl_pathv[i]);
			free(e);
			continue;
		}
		log_debug(LOG_SUBSYS_RETRONET, "[%s] Will return '%s'.",
		    conn_name(conn), g.gl_pathv[i]);
		rn_fileio_attrs_to_file_details(g.gl_pathv[i], &attrs,
		    &e->details);
		e->idx = ctx->file_list_count++;
		STAILQ_INSERT_TAIL(&ctx->file_list, e, link);
	}

 out:
	nabu_set_uint16(ctx->reply.file_list.matchCount,
	    (uint16_t)ctx->file_list_count);
	conn_send(conn, &ctx->reply.file_list, sizeof(ctx->reply.file_list));
	if (path != NULL) {
		free(path);
	}
	globfree(&g);
}

/*
 * rn_req_file_list_item --
 *	Handle the FILE-LIST-ITEM request.
 */
static void
rn_req_file_list_item(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.file_list_item,
			sizeof(ctx->request.file_list_item))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	struct rn_file_list_entry *e;
	unsigned int idx =
	    nabu_get_uint16(ctx->request.file_list_item.itemIndex);

	/* Start searching from the item we last returned. */
	for (e = ctx->cached_entry; e != NULL; e = STAILQ_NEXT(e, link)) {
		if (e->idx == idx) {
			goto gotit;
		}
	}

	for (e = STAILQ_FIRST(&ctx->file_list); e != ctx->cached_entry;
	     e = STAILQ_NEXT(e, link)) {
		if (e->idx == idx) {
			goto gotit;
		}
	}

 gotit:
	ctx->cached_entry = e;
	if (e != NULL) {
		memcpy(&ctx->reply.file_list_item,
		    &e->details, sizeof(ctx->reply.file_list_item));
	} else {
		/* Again, NO ERRORS.  Sigh. */
		memset(&ctx->reply.file_list_item, 0,
		    sizeof(ctx->reply.file_list_item));
		nabu_set_uint32(ctx->reply.file_list_item.file_size,
		    RN_NOENT);
	}
	conn_send(conn, &ctx->reply.file_list_item,
	    sizeof(ctx->reply.file_list_item));
}

/*
 * rn_req_file_details --
 *	Handle the FILE-DETAILS request.
 */
static void
rn_req_file_details(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct fileio_attrs attrs, *ap = &attrs;
	char *fname;
	int error;

	error = rn_file_getattr(ctx, ap);
	if (error != 0) {
		log_error("[%s] rn_file_getattr() failed: %s",
		    conn_name(conn), strerror(error));
		ap = NULL;
	}
	/* Copy the name before we scribble over it. */
	fname = strdup((char *)ctx->request.file_details.fileName);
	rn_fileio_attrs_to_file_details(fname, ap, &ctx->reply.file_details);
	free(fname);
	conn_send(conn, &ctx->reply.file_details,
	    sizeof(ctx->reply.file_details));
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
	if (! conn_recv(conn, &ctx->request.fh_details,
			sizeof(ctx->request.fh_details))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_details.fileHandle);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_details.fileHandle);
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
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_readseq,
			sizeof(ctx->request.fh_readseq))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_readseq.fileHandle);

	uint16_t length = nabu_get_uint16(ctx->request.fh_readseq.length);

	if (f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_readseq.fileHandle);
		length = 0;
	} else {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] slot %u length %u",
		    conn_name(conn), ctx->request.fh_readseq.fileHandle,
		    length);

		int error = stext_file_read(f, ctx->reply.fh_readseq.data,
		    &length);
		if (error != 0) {
			length = 0;
		}
	}
	nabu_set_uint16(ctx->reply.fh_readseq.returnLength, length);
	conn_send(conn, &ctx->reply.fh_readseq, length + 2);
}

/*
 * rn_req_fh_seek --
 *	Handle the FH-SEEK request.
 */
static void
rn_req_fh_seek(struct retronet_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;
	int error;

	/* Receive the request. */
	if (! conn_recv(conn, &ctx->request.fh_seek,
			sizeof(ctx->request.fh_seek))) {
		log_error("[%s] Failed to receive request.",
		    conn_name(conn));
		return;
	}

	f = stext_file_find(&ctx->stext, ctx->request.fh_seek.fileHandle);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.fh_seek.fileHandle);
		return;
	}

	int32_t offset = (int32_t)nabu_get_uint32(ctx->request.fh_seek.offset);
	int whence;

	switch (ctx->request.fh_seek.whence) {
	case RN_SEEK_SET:	whence = SEEK_SET;	break;
	case RN_SEEK_CUR:	whence = SEEK_CUR;	break;
	case RN_SEEK_END:	whence = SEEK_END;	break;
	default:
		log_info("[%s] Bad whence value from client: %u",
		    conn_name(conn), ctx->request.fh_seek.whence);
		goto bad;
	}

	error = stext_file_seek(f, &offset, whence);
	if (error) {
		log_error("[%s] stext_file_seek() failed: %s",
		    conn_name(conn), strerror(error));
 bad:
		/*
		 * Just try to get the current position to return.
		 * It's just so incredibly dumb to not have a way
		 * to return errors :-(
		 */
		offset = 0;
		(void) stext_file_seek(f, &offset, SEEK_CUR);
	}

	nabu_set_uint32(ctx->reply.fh_seek.offset, (uint32_t)offset);
	conn_send(conn, &ctx->reply.fh_seek, sizeof(ctx->reply.fh_seek));
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
		stext_context_init(&ctx->stext, conn, 0);
		STAILQ_INIT(&ctx->file_list);
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
	rn_file_list_free(ctx);
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

	if (! NABU_MSG_IS_RETRONET(msg)) {
		/* Not a RetroNet message. */
		return false;
	}

	if (! conn->retronet_enabled) {
		log_debug(LOG_SUBSYS_RETRONET, "[%s] RetroNet is not enabled.",
		    conn_name(conn));
		return false;
	}

	if (idx > retronet_request_type_count ||
	    retronet_request_types[idx].handler == NULL) {
		log_error("[%s] Unknown RetroNet request type 0x%02x.",
		    conn_name(conn), msg);
		return false;
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

	log_debug(LOG_SUBSYS_RETRONET, "[%s] Got %s.", conn_name(conn),
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
