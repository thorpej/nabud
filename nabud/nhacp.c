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
 * Support for the NABU HCCA Application Communication Protocol.
 *
 *    https://github.com/hanshuebner/nabu-figforth/blob/main/nabu-comms.md
 *
 * This implementation employs Postel's law in the following way:
 * Protocol versioning is not strictly enforced -- so long as the
 * messages are in the right format, we allow them.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define	NABU_PROTO_INLINES

#include "libnabud/fileio.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"
#include "libnabud/nabu_proto.h"
#include "libnabud/nhacp_proto.h"
#include "libnabud/nbsd_queue.h"

#include "conn.h"
#include "nhacp.h"
#include "stext.h"

struct nhacp_context {
	struct stext_context stext;
	uint16_t             nhacp_version;

	union {
		struct nhacp_request request;
		struct nhacp_response reply;
	};
};

#define	NABUD_NHACP_VERSION	NHACP_VERS_0_1

/*
 * Handle some NHACP protocol version differences.
 */
static bool
nhacp_reqlen_ok(struct nhacp_context *ctx, uint16_t reqlen)
{
	switch (ctx->nhacp_version) {
	case NHACP_VERS_0_0:
		/*
		 * No legitimate NHACP message can have a length with
		 * the most significant bit set.  If we have one, we
		 * assume the NABU has reset and is sending legacy
		 * messages (see nabu_proto.h).
		 */
		if (reqlen & 0x8000) {
			return false;
		}
		return true;

	default:
		/*
		 * This is essentially a more strict version of the
		 * 0.0 check, since it also ensures that the message
		 * will arrive in the allotted time.
		 */
		if (reqlen > NHACP_MTU) {
			return false;
		}
		return true;
	}
}

/*
 * The messages that contain a variable-sized data payload need to
 * sanity check that payload's length against how much of the max
 * payload was consumed by the protocol message itself.
 */
static uint16_t
nhacp_max_payload(struct nhacp_context *ctx, uint8_t type)
{
	uint16_t max_payload = NHACP_MAX_PAYLOAD;

	switch (type) {
	case NHACP_REQ_STORAGE_GET:
		if (ctx->nhacp_version == NHACP_VERS_0_0) {
			/* Backwards compatibility with old limit. */
			max_payload = NHACP_MTU_0_0 -
			    sizeof(struct nhacp_response_data_buffer);
		}
		break;

	case NHACP_REQ_STORAGE_PUT:
		if (ctx->nhacp_version == NHACP_VERS_0_0) {
			/* Backwards compatibility with old limit. */
			max_payload = NHACP_MTU_0_0 -
			    sizeof(struct nhacp_request_storage_put);
		}
		break;

	default:
		break;
	}

	return max_payload;
}

/*
 * nhacp_send_reply --
 *	Convenience function to send an NHACP reply.
 */
static void
nhacp_send_reply(struct nhacp_context *ctx, uint8_t type, uint16_t length)
{
	nabu_set_uint16(ctx->reply.length, length);
	ctx->reply.generic.type = type;
	conn_send(ctx->stext.conn, &ctx->reply,
	    length + sizeof(ctx->reply.length));
}

#define	ERRMAP(ue)		\
	{ .error_codes[0] = (ue), .error_codes[1] = NHACP_ ## ue }
#define	ERRMAP2(ue, ne)		\
	{ .error_codes[0] = (ue), .error_codes[1] = (ne) }

static const struct nhacp_error_map_entry {
	int		error_codes[2];
} nhacp_error_map[] = {
	ERRMAP2(0, NHACP_Eundefined),
	ERRMAP(ENOTSUP),
	ERRMAP(EPERM),
	ERRMAP(ENOENT),
	ERRMAP(EIO),
	ERRMAP(EBADF),
	ERRMAP(ENOMEM),
	ERRMAP(EACCES),
	ERRMAP(EBUSY),
	ERRMAP(EEXIST),
	ERRMAP(EISDIR),
	ERRMAP(ENFILE),
	ERRMAP2(EMFILE, NHACP_ENFILE),
	ERRMAP(EFBIG),
	ERRMAP(ENOSPC),
	ERRMAP2(ESPIPE, NHACP_ESEEK),

	/* Default */
	ERRMAP2(-1, NHACP_EIO),
};

#undef ERRMAP
#undef ERRMAP2

#define	ERRSTR(ne, s)	[(ne)] = s

/*
 * We use our own error string table -- we want to ensure that these
 * can be displayed with a potentially limited character set.
 */
static const char * const nhacp_error_strings[] = {
	ERRSTR(NHACP_ENOTSUP,	"OPERATION NOT SUPPORTED"),
	ERRSTR(NHACP_EPERM,	"OPERATION NOT PERMITTED"),
	ERRSTR(NHACP_ENOENT,	"NO SUCH FILE"),
	ERRSTR(NHACP_EIO,	"IO ERROR"),
	ERRSTR(NHACP_EBADF,	"INVALID FILE"),
	ERRSTR(NHACP_ENOMEM,	"OUT OF MEMORY"),
	ERRSTR(NHACP_EACCES,	"ACCESS DENIED"),
	ERRSTR(NHACP_EBUSY,	"RESOURCE BUSY"),
	ERRSTR(NHACP_EEXIST,	"FILE EXISTS"),
	ERRSTR(NHACP_EISDIR,	"FILE IS A DIRECTORY"),
	ERRSTR(NHACP_EINVAL,	"BAD REQUEST"),
	ERRSTR(NHACP_ENFILE,	"TOO MANY OPEN FILES"),
	ERRSTR(NHACP_EFBIG,	"FILE TOO BIG"),
	ERRSTR(NHACP_ENOSPC,	"OUT OF SPACE"),
	ERRSTR(NHACP_ESEEK,	"ILLEGAL SEEK"),
};
static const unsigned int nhacp_error_string_count =
    sizeof(nhacp_error_strings) / sizeof(nhacp_error_strings[0]);

#undef ERRSTR

static const struct nhacp_error_map_entry *
nhacp_error_map_find(int unix_err, uint8_t nhacp_err)
{
	const struct nhacp_error_map_entry *e;
	const int idx = unix_err == -1;
	const int code = unix_err == -1 ? nhacp_err : unix_err;

	for (e = nhacp_error_map; e->error_codes[0] != -1; e++) {
		if (e->error_codes[idx] == code) {
			break;
		}
	}
	return e;
}

/*
 * nhacp_error_from_unix --
 *	Map a Unix errno value to an NHACP error code.
 */
static uint8_t
nhacp_error_from_unix(int unix_err)
{
	assert(unix_err >= 0);
	return nhacp_error_map_find(unix_err, 0)->error_codes[1];
}

#if 0
/*
 * nhacp_error_to_unix --
 *	Map an NHACP error code to a Unix errno value.
 */
static int
nhacp_error_to_unix(uint8_t nhacp_err)
{
	return nhacp_error_map_find(-1, nhacp_err)->error_codes[0];
}
#endif

/*
 * nhacp_send_error_details --
 *	Convenience function to send an NHACP error.
 */
static void
nhacp_send_error_details(struct nhacp_context *ctx, uint16_t code,
    size_t max_message_length)
{
	const char *error_message = NULL;
	size_t message_length = 0;
	char message_buffer[sizeof("UNKNOWN ERROR XXXXX")];

	if (max_message_length != 0) {
		if (code >= nhacp_error_string_count ||
		    (error_message = nhacp_error_strings[code]) == NULL) {
			snprintf(message_buffer, sizeof(message_buffer),
			    "UNKNOWN ERROR %u", code);
			error_message = message_buffer;
		}
		message_length = strlen(error_message);

		assert(max_message_length < 256);
		if (message_length > max_message_length) {
			message_length = max_message_length;
		}
	}

	nabu_set_uint16(ctx->reply.error.code, code);
	ctx->reply.error.message_length = (uint8_t)message_length;
	if (message_length != 0) {
		memcpy(ctx->reply.error.message, error_message,
		    message_length);
	}

	nhacp_send_reply(ctx, NHACP_RESP_ERROR,
	    sizeof(ctx->reply.error) + message_length);
}

/*
 * nhacp_send_error --
 *	Convenience wrapper around nhacp_send_error_details().
 */
static void
nhacp_send_error(struct nhacp_context *ctx, uint16_t code)
{
	/* Original NHACP draft always sent error details. */
	nhacp_send_error_details(ctx, code,
	    ctx->nhacp_version == NHACP_VERS_0_0 ? 255 : 0);
}

/*
 * nhacp_send_ok --
 *	Convenience function to send an NHACP OK response.
 */
static void
nhacp_send_ok(struct nhacp_context *ctx)
{
	nhacp_send_reply(ctx, NHACP_RESP_OK, sizeof(ctx->reply.ok));
}

/*
 * nhacp_send_data_buffer --
 *	Convenience function to send a DATA-BUFFER response.
 */
static void
nhacp_send_data_buffer(struct nhacp_context *ctx, uint16_t length)
{
	nabu_set_uint16(ctx->reply.data_buffer.length, length);
	nhacp_send_reply(ctx, NHACP_RESP_DATA_BUFFER,
	    sizeof(ctx->reply.data_buffer) + length);
}

/*****************************************************************************
 * Request handling
 *****************************************************************************/

static int
nhacp_o_flags_to_fileio(uint16_t nhacp_o_flags, int *fileio_o_flagsp)
{

	switch (nhacp_o_flags & NHACP_O_ACCMASK) {
	case NHACP_O_RDWR:
		*fileio_o_flagsp = FILEIO_O_RDWR;
		break;

	case NHACP_O_RDONLY:
		*fileio_o_flagsp = FILEIO_O_RDONLY;
		break;

	default:
		/*
		 * Not actually possible because NHACP_O_RDWR == 0.
		 * Compiler should DCE this into a puff of greasy smoke.
		 */
		return EINVAL;
	}
	if (nhacp_o_flags & NHACP_O_CREAT) {
		*fileio_o_flagsp |= FILEIO_O_CREAT;
	}
	if (nhacp_o_flags & NHACP_O_EXCL) {
		*fileio_o_flagsp |= FILEIO_O_EXCL;
	}

	return 0;
}

/*
 * nhacp_req_storage_open --
 *	Handle the STORAGE-OPEN request.
 */
static void
nhacp_req_storage_open(struct nhacp_context *ctx)
{
	struct fileio_attrs attrs;
	struct stext_file *f;
	int fileio_o_flags;
	uint16_t nhacp_o_flags;
	int error;

	/*
	 * The requested URL is no more than 255 bytes long, and we
	 * know the buffer it's in is longer than the maximum size
	 * STORAGE-OPEN request, so we can simply NUL-terminate in
	 * situ.
	 */
	ctx->request.storage_open.url_string[
	    ctx->request.storage_open.url_length] = '\0';

	/*
	 * NHACP-0.0 did not define any open flags, even though it
	 * had a slot for them.
	 */
	if (ctx->nhacp_version == NHACP_VERS_0_0) {
		nhacp_o_flags = NHACP_O_RDWR | NHACP_O_CREAT;
	} else {
		nhacp_o_flags =
		    nabu_get_uint16(ctx->request.storage_open.flags);
	}

	error = nhacp_o_flags_to_fileio(nhacp_o_flags, &fileio_o_flags);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
		return;
	}

	error = stext_file_open(&ctx->stext,
	    (const char *)ctx->request.storage_open.url_string,
	    ctx->request.storage_open.req_slot, &attrs, fileio_o_flags, &f);

	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		ctx->reply.storage_loaded.slot = stext_file_slot(f);
		nabu_set_uint32(ctx->reply.storage_loaded.length,
		    (uint32_t)attrs.size);
		nhacp_send_reply(ctx, NHACP_RESP_STORAGE_LOADED,
		    sizeof(ctx->reply.storage_loaded));
	}
}

/*
 * nhacp_req_storage_get --
 *	Handle the STORAGE-GET request.
 */
static void
nhacp_req_storage_get(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_get.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.storage_get.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	uint32_t offset = nabu_get_uint32(ctx->request.storage_get.offset);
	uint16_t length = nabu_get_uint16(ctx->request.storage_get.length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u offset %u length %u",
	    conn_name(ctx->stext.conn), ctx->request.storage_get.slot,
	    offset, length);

	if (length > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_GET)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	int error = stext_file_pread(f, ctx->reply.data_buffer.data,
	    offset, &length);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_data_buffer(ctx, length);
	}
}

/*
 * nhacp_req_storage_put --
 *	Handle the STORAGE-PUT request.
 */
static void
nhacp_req_storage_put(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_put.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.storage_put.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	uint32_t offset = nabu_get_uint32(ctx->request.storage_put.offset);
	uint16_t length = nabu_get_uint16(ctx->request.storage_put.length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u offset %u length %u",
	    conn_name(ctx->stext.conn), ctx->request.storage_put.slot,
	    offset, length);

	if (length > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_PUT)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	int error = stext_file_pwrite(f, ctx->request.storage_put.data,
	    offset, length);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_ok(ctx);
	}
}

/*
 * nhacp_req_storage_get_block --
 *	Handle the STORAGE-GET-BLOCK request.
 */
static void
nhacp_req_storage_get_block(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_get_block.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.storage_get_block.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	uint32_t blkno =
	    nabu_get_uint32(ctx->request.storage_get_block.block_number);
	uint16_t blklen =
	    nabu_get_uint16(ctx->request.storage_get_block.block_length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u blkno %u blklen %u",
	    conn_name(ctx->stext.conn), ctx->request.storage_get_block.slot,
	    blkno, blklen);

	/*
	 * Make sure we won't overflow the 32-bit file offsets we use
	 * in the storage extensions.
	 */
	uint64_t offset = (uint64_t)blkno * blklen;
	if (offset > UINT32_MAX - blklen + 1) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] offset %llu too large",
		    conn_name(ctx->stext.conn), (unsigned long long)offset);
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	if (blklen > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_GET_BLOCK)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	const uint16_t save_blklen = blklen;

	int error = stext_file_pread(f, ctx->reply.data_buffer.data,
	    (uint32_t)offset, &blklen);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else if (blklen != save_blklen) {
		/* Partial reads not allowed for block I/O. */
		nhacp_send_error(ctx, NHACP_EINVAL);
	} else {
		nhacp_send_data_buffer(ctx, blklen);
	}
}

/*
 * nhacp_req_storage_put_block --
 *	Handle the STORAGE-PUT-BLOCK request.
 */
static void
nhacp_req_storage_put_block(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_put_block.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.storage_put_block.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	uint32_t blkno =
	    nabu_get_uint32(ctx->request.storage_put_block.block_number);
	uint16_t blklen =
	    nabu_get_uint16(ctx->request.storage_put_block.block_length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u blkno %u blklen %u",
	    conn_name(ctx->stext.conn), ctx->request.storage_put_block.slot,
	    blkno, blklen);

	/*
	 * Make sure we won't overflow the 32-bit file offsets we use
	 * in the storage extensions.
	 */
	uint64_t offset = (uint64_t)blkno * blklen;
	if (offset > UINT32_MAX - blklen + 1) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] offset %llu too large",
		    conn_name(ctx->stext.conn), (unsigned long long)offset);
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	if (blklen > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_PUT_BLOCK)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	/* Enforce no-extending-writes for block I/O. */
	struct fileio_attrs attrs;
	int error = stext_file_getattr(f, &attrs);
	if (error != 0) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] stext_file_getattr() failed: %s",
		     conn_name(ctx->stext.conn), strerror(error));
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
		return;
	}
	if (offset + blklen > attrs.size) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Request would extend file (size = %lld)",
		    conn_name(ctx->stext.conn), (long long)attrs.size);
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	error = stext_file_pwrite(f, ctx->request.storage_put_block.data,
	    (uint32_t)offset, blklen);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_ok(ctx);
	}
}

/*
 * nhacp_req_get_date_time --
 *	Handle the GET-DATE-TIME request.
 */
static void
nhacp_req_get_date_time(struct nhacp_context *ctx)
{
	struct tm tm_store, *tm;
	time_t now = time(NULL);

	if (now == (time_t)-1) {
		log_error("[%s] unable to get current time: %s",
		    conn_name(ctx->stext.conn), strerror(errno));
		memset(&tm_store, 0, sizeof(tm_store));
		tm = &tm_store;
	} else {
		tm = localtime_r(&now, &tm_store);
	}

	/*
	 * The date and time portions of the DATE-TIME response
	 * are adjacent to each other with no intervening NUL
	 * provision, and we know there is room at the end of
	 * the response for a NUL terminator, so we can do this
	 * with a single strftime() that emits:
	 *
	 *	YYYYMMDDHHMMSS\0
	 */
	strftime((char *)ctx->reply.date_time.yyyymmdd,
	    sizeof(ctx->reply.date_time.yyyymmdd) +
	    sizeof(ctx->reply.date_time.hhmmss) + 1,
	    "%Y%m%d%H%M%S", tm);

	nhacp_send_reply(ctx, NHACP_RESP_DATE_TIME,
	    sizeof(ctx->reply.date_time));
}

/*
 * nhacp_req_storage_close --
 *	Handle the STORAGE-CLOSE request.
 */
static void
nhacp_req_storage_close(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_close.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.storage_close.slot);
		return;
	}
	log_debug(LOG_SUBSYS_NHACP, "[%s] Closing file at slot %u.",
	    conn_name(ctx->stext.conn), stext_file_slot(f));
	stext_file_close(f);
}

/*
 * nhacp_req_get_error_details --
 *	Handle the GET-ERROR-DETAILS request.
 */
static void
nhacp_req_get_error_details(struct nhacp_context *ctx)
{
	nhacp_send_error_details(ctx,
	    nabu_get_uint16(ctx->request.get_error_details.code),
	    ctx->request.get_error_details.max_message_len);
}

#define	HANDLER_ENTRY(v, n)						\
	[(v)] = {							\
		.handler    = nhacp_req_ ## n ,				\
		.debug_desc = #v ,					\
		.min_reqlen = sizeof(struct nhacp_request_ ## n ),	\
	}

static const struct {
	void		(*handler)(struct nhacp_context *);
	const char	*debug_desc;
	ssize_t		min_reqlen;
} nhacp_request_types[] = {
	HANDLER_ENTRY(NHACP_REQ_STORAGE_OPEN,      storage_open),
	HANDLER_ENTRY(NHACP_REQ_STORAGE_GET,       storage_get),
	HANDLER_ENTRY(NHACP_REQ_STORAGE_PUT,       storage_put),
	HANDLER_ENTRY(NHACP_REQ_GET_DATE_TIME,     get_date_time),
	HANDLER_ENTRY(NHACP_REQ_STORAGE_CLOSE,     storage_close),
	HANDLER_ENTRY(NHACP_REQ_GET_ERROR_DETAILS, get_error_details),
	HANDLER_ENTRY(NHACP_REQ_STORAGE_GET_BLOCK, storage_get_block),
	HANDLER_ENTRY(NHACP_REQ_STORAGE_PUT_BLOCK, storage_put_block),
};
static const unsigned int nhacp_request_type_count =
    sizeof(nhacp_request_types) / sizeof(nhacp_request_types[0]);

#undef HANDLER_ENTRY

/*
 * nhacp_context_alloc --
 *	Allocate an NHACP context for the specified connection.
 */
static struct nhacp_context *
nhacp_context_alloc(struct nabu_connection *conn)
{
	struct nhacp_context *ctx = calloc(1, sizeof(*ctx));
	if (ctx != NULL) {
		stext_context_init(&ctx->stext, conn);
	}
	return ctx;
}

/*
 * nhacp_context_free --
 *	Free and NHACP context and all associated resources.
 */
static void
nhacp_context_free(struct nhacp_context *ctx)
{
	stext_context_fini(&ctx->stext);
	free(ctx);
}

/*
 * nhacp_request_check --
 *	Validates the incoming request.
 *
 *	Returns:	-1	request type unknown
 *			0	everything is OK
 *			other	the expected minimum size
 */
static ssize_t
nhacp_request_check(uint8_t req, uint16_t length)
{
	/* Max message length has already been checked. */
	assert(length <= NHACP_MAX_MESSAGELEN);

	if (req < nhacp_request_type_count) {
		if (nhacp_request_types[req].handler == NULL) {
			return -1;
		}
		if (length >= nhacp_request_types[req].min_reqlen) {
			return 0;
		}
		return nhacp_request_types[req].min_reqlen;
	}
	return -1;
}

/*
 * nhacp_request --
 *	Invoke the handler for the specified request.
 */
static inline void
nhacp_request(struct nhacp_context *ctx)
{
	log_debug(LOG_SUBSYS_NHACP, "[%s] Got %s.", conn_name(ctx->stext.conn),
	    nhacp_request_types[ctx->request.generic.type].debug_desc);
	(*nhacp_request_types[ctx->request.generic.type].handler)(ctx);
}

/*
 * nhacp_recv_start --
 *	Receive and validate the versioned START-NHACP message.
 */
static bool
nhacp_recv_start(struct nabu_connection *conn, uint16_t *versionp)
{
	struct nabu_msg_start_nhacp start_nhacp;

	conn_start_watchdog(conn, 1);

	/*
	 * We've already received the first byte (the message type);
	 * receive the remaining 5.
	 */
	if (! conn_recv(conn, &start_nhacp.magic, sizeof(start_nhacp) - 1)) {
		if (conn_check_state(conn)) {
			/* Error not already logged in this case. */
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] conn_recv() of START-NHACP message failed.",
			    conn_name(conn));
			return false;
		}
	}

	if (! NHACP_MAGIC_IS_VALID(start_nhacp.magic)) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Invalid START-NHACP magic: 0x%02x 0x%02x 0x%02x",
		    conn_name(conn), start_nhacp.magic[0],
		    start_nhacp.magic[1], start_nhacp.magic[2]);
		return false;
	}

	*versionp = nabu_get_uint16(start_nhacp.version);

	/* We do enforce versioning here, however. */
	switch (*versionp) {
	case NHACP_VERS_0_0:
	case NHACP_VERS_0_1:
		return true;

	default:
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unsupported NHACP version 0x%04x.",
		    conn_name(conn), *versionp);
		return false;
	}
}

/*
 * nhacp_start --
 *	Enter NHACP mode on this connection.
 */
bool
nhacp_start(struct nabu_connection *conn, uint8_t msg)
{
	struct nhacp_context *ctx;
	extern char nabud_version[];
	uint16_t reqlen;
	uint16_t version;
	ssize_t minlen;

	switch (msg) {
	case NABU_MSG_START_NHACP_0_0:		/* original draft */
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Got NABU_MSG_START_NHACP_0_0.", conn_name(conn));
		version = NHACP_VERS_0_0;
		break;

	case NABU_MSG_START_NHACP:		/* versioned START-NHACP */
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Got NABU_MSG_START_NHACP.", conn_name(conn));
		if (! nhacp_recv_start(conn, &version)) {
			/*
			 * Not a valid START-NHACP, or not a version
			 * that we support.
			 */
			return false;
		}
		break;

	default:
		/* Not a NHACP start message. */
		return false;
	}

	/*
	 * If we failed to allocate a context, just don't send
	 * a reply -- act as if this were an unrecognized message.
	 */
	if ((ctx = nhacp_context_alloc(conn)) == NULL) {
		log_error("[%s] Failed to allocate NHACP context.",
		    conn_name(conn));
		return true;
	}
	ctx->nhacp_version = version;

	/*
	 * Send a NHACP-STARTED response.  We know there's room at the end
	 * for a NUL terminator.
	 */
	nabu_set_uint16(ctx->reply.nhacp_started.version, NABUD_NHACP_VERSION);
	snprintf((char *)ctx->reply.nhacp_started.adapter_id, 256, "%s-%s",
	    getprogname(), nabud_version);
	ctx->reply.nhacp_started.adapter_id_length =
	    (uint8_t)strlen((char *)ctx->reply.nhacp_started.adapter_id);
	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] Sending proto version: 0x%04x server version: %s",
	    conn_name(conn), NABUD_NHACP_VERSION,
	    (char *)ctx->reply.nhacp_started.adapter_id);
	nhacp_send_reply(ctx, NHACP_RESP_NHACP_STARTED,
	    sizeof(ctx->reply.nhacp_started) +
	    ctx->reply.nhacp_started.adapter_id_length);

	/*
	 * Now enter NHACP mode until we are asked to exit or until
	 * we detect something is awry with the NABU.
	 */
	log_info("[%s] Entering NHACP-%d.%d mode.", conn_name(conn),
	    NHACP_VERS_MAJOR(ctx->nhacp_version),
	    NHACP_VERS_MINOR(ctx->nhacp_version));

	for (;;) {
		/* We want to block "forever" waiting for requests. */
		conn_stop_watchdog(conn);

		/*
		 * Receive the first (LSB) byte of the length.  We need
		 * to do this to guard against a NABU that's been reset.
		 */
		log_debug(LOG_SUBSYS_NHACP, "[%s] Waiting for NABU.",
		     conn_name(conn));
		if (! conn_recv_byte(conn, &ctx->request.length[0])) {
 recv_failure:
			if (! conn_check_state(conn)) {
				/* Error already logged. */
				break;
			}
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] conn_recv_byte() failed, "
			    "continuing event loop.", conn_name(conn));
			continue;
		}

		/*
		 * Now that we have the first byte, enable the watchdog.
		 * The protocol says that each individual message transfer
		 * must complete within 1 second.
		 */
		conn_start_watchdog(conn, 1);

		/* Now receive the MSB of the length. */
		if (! conn_recv_byte(conn, &ctx->request.length[1])) {
			goto recv_failure;
		}
		reqlen = nabu_get_uint16(ctx->request.length);

		if (reqlen == 0) {
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] Received 0-length request.",
			    conn_name(conn));
			continue;
		}

		if (! nhacp_reqlen_ok(ctx, reqlen)) {
			log_error("[%s] Bogus request length: 0x%04x - "
			    "exiting NHACP mode.", conn_name(conn), reqlen);
			break;
		}

		/* Ok, receive the message. */
		if (! conn_recv(conn, &ctx->request.max_request, reqlen)) {
			goto recv_failure;
		}

		/*
		 * Check for END-PROTOCOL before we do anything else.
		 * There's no payload and no reply -- we just get out.
		 */
		if (ctx->request.generic.type == NHACP_REQ_END_PROTOCOL) {
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] Got NHACP_REQ_END_PROTOCOL.",
			    conn_name(conn));
			break;
		}

		/*
		 * Check that the client sent the bare-minimum for the
		 * request to be valid.
		 */
		minlen = nhacp_request_check(ctx->request.generic.type, reqlen);
		if (minlen == -1) {
			log_error("[%s] Unknown NHACP request: 0x%02x",
			    conn_name(conn), ctx->request.generic.type);
			/* Just skip it. */
			continue;
		} else if (minlen != 0) {
			log_error("[%s] Runt NHACP request: %u < %zd",
			    conn_name(conn), reqlen, minlen);
			/* Just skip it. */
			continue;
		}

		/* Everything checks out -- handle the request. */
		nhacp_request(ctx);
	}

	log_info("[%s] Exiting NHACP mode.", conn_name(conn));
	nhacp_context_free(ctx);
	return true;
}
