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
 */

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define	NABU_PROTO_INLINES

#include "libnabud/crc8_wcdma.h"
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
	struct stext_context      stext;
	LIST_ENTRY(nhacp_context) link;
	bool                      linked;
	uint8_t                   session_id;
	uint16_t                  nhacp_version;
	uint16_t                  nhacp_options;

	union {
		struct nhacp_request request;
		struct nhacp_response reply;
	};
};

static inline size_t
nhacp_crc_len(uint16_t options)
{
	if (options & NHACP_OPTION_CRC8) {
		return 1;
	}
	return 0;
}

struct nhacp_file_list_entry {
	STAILQ_ENTRY(nhacp_file_list_entry) link;
	struct nhacp_response_dir_entry *dir_entry;
};

struct nhacp_file_private {
	STAILQ_HEAD(, nhacp_file_list_entry) file_list;
	bool is_directory;
	bool is_writable;
};

/* We support up to version 0.1 of the NHACP protocol. */
#define	NABUD_NHACP_VERSION	NHACP_VERS_0_1

/* We support these NHACP options. */
#define	NABUD_NHACP_OPTIONS	NHACP_OPTION_CRC8

/*
 * File private data routines.
 */
static struct nhacp_file_list_entry *
nhacp_file_list_entry_alloc(size_t namelen)
{
	struct nhacp_response_dir_entry *de = calloc(1, sizeof(*de) + namelen);
	if (de == NULL) {
		return NULL;
	}

	struct nhacp_file_list_entry *e = calloc(1, sizeof(*e));
	if (e == NULL) {
		free(de);
		return NULL;
	}

	e->dir_entry = de;
	return e;
}

static void
nhacp_file_list_entry_free(struct nhacp_file_list_entry *e)
{
	if (e->dir_entry != NULL) {
		free(e->dir_entry);
	}
	free(e);
}

static void
nhacp_file_free_file_list(struct nhacp_file_private *fp)
{
	struct nhacp_file_list_entry *e;

	while ((e = STAILQ_FIRST(&fp->file_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&fp->file_list, link);
		nhacp_file_list_entry_free(e);
	}
}

static void
nhacp_file_private_init(void *v)
{
	struct nhacp_file_private *fp = v;

	STAILQ_INIT(&fp->file_list);
}

static void
nhacp_file_private_fini(void *v)
{
	struct nhacp_file_private *fp = v;

	nhacp_file_free_file_list(fp);
}

static bool
nhacp_file_is_directory(struct stext_file *f)
{
	struct nhacp_file_private *fp = stext_file_private(f);

	return fp->is_directory;
}

/*
 * nhacp_context_free --
 *	Free and NHACP context and all associated resources.
 */
static void
nhacp_context_free(struct nhacp_context *ctx)
{
	if (ctx->linked) {
		LIST_REMOVE(ctx, link);
	}
	stext_context_fini(&ctx->stext);
	free(ctx);
}

/*
 * nhacp_context_alloc --
 *	Allocate an NHACP context for the specified connection.
 */
static struct nhacp_context *
nhacp_context_alloc(struct nabu_connection *conn, uint8_t session_id)
{
	struct nhacp_context *ctx = calloc(1, sizeof(*ctx));
	ctx->session_id = session_id;
	stext_context_init(&ctx->stext, conn,
	    sizeof(struct nhacp_file_private),
	    nhacp_file_private_init, nhacp_file_private_fini);
	return ctx;
}

/*
 * nhacp_context_lookup --
 *	Look up an NHACP context by session ID.
 */
static struct nhacp_context *
nhacp_context_lookup(struct nabu_connection *conn, uint8_t session_id)
{
	struct nhacp_context *ctx;

	LIST_FOREACH(ctx, &conn->nhacp_sessions, link) {
		if (ctx->session_id == session_id) {
			return ctx;
		}
	}
	return NULL;
}

/*
 * nhacp_context_init --
 *	Initialize (and link up) an NHACP context.
 */
static bool
nhacp_context_init(struct nabu_connection *conn, struct nhacp_context *ctx)
{
	assert(! ctx->linked);
	assert(ctx->session_id == NHACP_SESSION_SYSTEM ||
	       ctx->session_id == NHACP_SESSION_CREATE);
	assert(ctx->session_id != NHACP_SESSION_SYSTEM ||
	       nhacp_context_lookup(conn, NHACP_SESSION_SYSTEM) == NULL);

	if (ctx->session_id == NHACP_SESSION_CREATE) {
		uint8_t session_id;

		for (session_id = NHACP_SESSION_SYSTEM + 1;
		     session_id < NHACP_SESSION_CREATE;
		     session_id++) {
			if (nhacp_context_lookup(conn, session_id) == NULL) {
				break;
			}
		}
		if (session_id == NHACP_SESSION_CREATE) {
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] Out of NHACP sessions.", conn_name(conn));
			return false;
		}
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Allocated session ID %u.", conn_name(conn),
		    session_id);
		ctx->session_id = session_id;
	}

	ctx->linked = true;
	LIST_INSERT_HEAD(&conn->nhacp_sessions, ctx, link);

	return true;
}

/*
 * nhacp_conn_reset --
 *	Reset the connection's NHACP state, preserving the specified
 *	context if it is on the connection's list.
 */
static void
nhacp_conn_reset(struct nabu_connection *conn, struct nhacp_context *octx)
{
	struct nhacp_context *ctx, *tctx;

	LIST_FOREACH_SAFE(ctx, &conn->nhacp_sessions, link, tctx) {
		if (ctx == octx) {
			stext_context_fini(&ctx->stext);
		} else {
			nhacp_context_free(ctx);
		}
	}
}

/*
 * Handle some NHACP protocol version differences.
 */
static bool
nhacp_reqlen_ok(struct nhacp_context *ctx, uint16_t reqlen)
{
	if (reqlen == 0) {
		return false;
	}

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
 * nhacp_time_from_unix --
 *	Convert an absolute Unix time to local NHACP DATE-TIME.
 */
static void
nhacp_time_from_unix(time_t t, struct nhacp_date_time *dt)
{
	struct tm tm_store, *tm;
	char buf[sizeof(*dt) + 1];

	if (t == (time_t)-1) {
		memset(&tm_store, 0, sizeof(tm_store));
		tm = &tm_store;
	} else {
		tm = localtime_r(&t, &tm_store);
	}

	/*
	 * The fields of the DATE-TIME response are adjacent to each
	 * other with no intervening NUL provision, so we can just do
	 * this with a single strftime() that emits:
	 *
	 *	YYYYMMDDHHMMSS\0
	 */
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	memcpy(dt, buf, sizeof(*dt));
}

/*
 * nhacp_file_attrs_from_fileio --
 *	Convert fileio_attrs to nhacp_file_attrs.
 */
static void
nhacp_file_attrs_from_fileio(const struct fileio_attrs *fa,
    struct nhacp_file_attrs *na)
{
	uint32_t size = fa->size > UINT32_MAX ? UINT32_MAX : (uint32_t)fa->size;
	uint16_t flags = NHACP_AF_RD;	/* assume readability */

	if (fa->is_directory) {
		flags |= NHACP_AF_DIR;
	}
	if (fa->is_writable) {
		flags |= NHACP_AF_WR;
	}
	nhacp_time_from_unix(fa->mtime, &na->mtime);
	nabu_set_uint16(na->flags, flags);
	nabu_set_uint32(na->file_size, size);
}

/*
 * nhacp_crc_ptr --
 *	Return a pointer to where the CRC is located in the
 *	current message, or NULL if there is no CRC.  The
 *	length field in the NHACP frame MUST already include
 *	the CRC, if CRC is being used.
 *
 *	N.B. this works for both requests *and* replies due to
 *	how we share buffer space between them.
 */
static uint8_t *
nhacp_crc_ptr(struct nhacp_context *ctx, uint16_t options)
{
	size_t crclen = nhacp_crc_len(options);

#ifdef HAVE_STATIC_ASSERT
	_Static_assert(
	    offsetof(struct nhacp_context, request) ==
	    offsetof(struct nhacp_context, reply),
	    "Request and response do not align.");

	_Static_assert(
	    offsetof(struct nhacp_request, max_request) ==
	    offsetof(struct nhacp_response, max_response),
	    "Max request and max response to not align.");

	_Static_assert(
	    offsetof(struct nhacp_request_max, payload) ==
	    offsetof(struct nhacp_response_max, payload),
	    "Request and response payloads to not align.");
#endif /* HAVE_STATIC_ASSERT */

	if (crclen == 0) {
		return NULL;
	}

	uint16_t length = nabu_get_uint16(ctx->reply.length);

	/*
	 * The CRC is located immediately after the request / reply
	 * payload.  The length field includes the CRC.
	 */
	return &ctx->reply.max_response.payload[length -
	    offsetof(struct nhacp_response_max, payload) - crclen];
}

/*
 * nhacp_send_reply --
 *	Convenience function to send an NHACP reply.
 */
static void
nhacp_send_reply(struct nhacp_context *ctx, uint8_t type, uint16_t length)
{
	size_t crclen = nhacp_crc_len(ctx->nhacp_options);

	length += crclen;
	assert(length <= NHACP_MAX_MESSAGELEN);

	nabu_set_uint16(ctx->reply.length, length);
	ctx->reply.generic.type = type;

	/*
	 * The packet data is now fully constructed; we can compute
	 * the CRC, if enabled.
	 */
	if (ctx->nhacp_options & NHACP_OPTION_CRC8) {
		assert(crclen == 1);

		uint8_t *crc_ptr = nhacp_crc_ptr(ctx, ctx->nhacp_options);
		assert(crc_ptr != NULL);

		uint8_t crc = crc8_wcdma_init();
		crc = crc8_wcdma_update(&ctx->reply,
		    (uintptr_t)crc_ptr - (uintptr_t)&ctx->reply, crc);
		crc = crc8_wcdma_fini(crc);

		*crc_ptr = crc;
	}

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
	ERRMAP(ENOTDIR),
	ERRMAP(ENFILE),
	ERRMAP2(EMFILE, NHACP_ENFILE),
	ERRMAP(EFBIG),
	ERRMAP(ENOSPC),
	ERRMAP2(ESPIPE, NHACP_ESEEK),
#ifdef HAVE_EFTYPE
	ERRMAP2(EFTYPE, NHACP_EPERM),
#endif /* HAVE_EFTYPE */
	ERRMAP2(EXDEV, NHACP_EPERM),
	ERRMAP2(EROFS, NHACP_EPERM),
	ERRMAP(ENOTEMPTY),
	ERRMAP(ESRCH),
	ERRMAP(EAGAIN),

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
	ERRSTR(NHACP_ENOTDIR,	"FILE IS NOT A DIRECTORY"),
	ERRSTR(NHACP_ENOTEMPTY,	"DIRECTORY IS NOT EMPTY"),
	ERRSTR(NHACP_ESRCH,	"NO SUCH PROCESS"),
	ERRSTR(NHACP_ENSESS,	"TOO MANY SESSIONS"),
	ERRSTR(NHACP_EAGAIN,	"TRY AGAIN LATER"),
	ERRSTR(NHACP_EROFS,	"FILE IS WRITE-PROTECTED"),
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

/*
 * nhacp_send_uint32 --
 *	Convenience function to send a UINT32-VALUE response.
 */
static void
nhacp_send_uint32(struct nhacp_context *ctx, uint32_t val)
{
	nabu_set_uint32(ctx->reply.uint32_value.value, val);
	nhacp_send_reply(ctx, NHACP_RESP_UINT32_VALUE,
	    sizeof(ctx->reply.uint32_value));
}

/*****************************************************************************
 * Request handling
 *****************************************************************************/

/*
 * nhacp_req_hello --
 *	Handle the HELLO request.
 */
static void
nhacp_req_hello(struct nhacp_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	extern char nabud_version[];

	if (! NHACP_MAGIC_IS_VALID(ctx->request.hello.magic)) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Invalid HELLO magic: 0x%02x 0x%02x 0x%02x",
		    conn_name(conn),
		    ctx->request.hello.magic[0],
		    ctx->request.hello.magic[1],
		    ctx->request.hello.magic[2]);
		/* Bogus magic -- just ignore it. */
		return;
	}

	uint16_t version = nabu_get_uint16(ctx->request.hello.version);
	uint16_t options = nabu_get_uint16(ctx->request.hello.options);

	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] Client request NHACP version 0x%04x options 0x%04x.",
	    conn_name(conn), version, options);

	if (options & ~NABUD_NHACP_OPTIONS) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unsupported NHACP options 0x%04x.",
		    conn_name(conn), options & ~NABUD_NHACP_OPTIONS);
		/* Just ignore this. */
		return;
	}

	switch (version) {
	/*
	 * Not allowed to start NHACP-0.0 this way.
	 */
	case NHACP_VERS_0_1:
		break;

	default:
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unsupported NHACP version 0x%04x.",
		    conn_name(conn), version);
		/* Just ignore this. */
		return;
	}

	ctx->nhacp_version = version;
	ctx->nhacp_options = options;

	if (ctx->session_id == NHACP_SESSION_SYSTEM) {
		/*
		 * HELLO with the SYSTEM session means we need to
		 * reset everything and start afresh.
		 */
		nhacp_conn_reset(ctx->stext.conn, ctx);
	} else if (ctx->session_id != NHACP_SESSION_CREATE) {
		/*
		 * Can't request a new session with an ID that might
		 * already be in-use.
		 */
		nhacp_send_error(ctx, NHACP_EINVAL);
		if (! ctx->linked) {
			nhacp_context_free(ctx);
		}
		return;
	}

	if (ctx->linked) {
		assert(ctx->session_id == NHACP_SESSION_SYSTEM);
	} else if (! nhacp_context_init(conn, ctx)) {
		nhacp_send_error(ctx, NHACP_ENSESS);
		nhacp_context_free(ctx);
		return;
	}

	ctx->reply.session_started.session_id = ctx->session_id;
	nabu_set_uint16(ctx->reply.session_started.version,
	    NABUD_NHACP_VERSION);
	snprintf((char *)ctx->reply.session_started.adapter_id, 256, "%s-%s",
	    getprogname(), nabud_version);
	ctx->reply.session_started.adapter_id_length =
	   (uint8_t)strlen((char *)ctx->reply.session_started.adapter_id);
	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] Sending proto version: 0x%04x server version: %s",
	    conn_name(conn), NABUD_NHACP_VERSION,
	    (char *)ctx->reply.session_started.adapter_id);
	log_info("[%s] Established NHAP-%d.%d session %u.", conn_name(conn),
	    NHACP_VERS_MAJOR(ctx->nhacp_version),
	    NHACP_VERS_MINOR(ctx->nhacp_version),
	    ctx->session_id);
	if (ctx->nhacp_options & NHACP_OPTION_CRC8) {
		log_info("[%s] session %u: CRC-8/WCDMA FCS option enabled.",
		    conn_name(conn), ctx->session_id);
	}
	nhacp_send_reply(ctx, NHACP_RESP_SESSION_STARTED,
	    sizeof(ctx->reply.session_started) +
	    ctx->reply.session_started.adapter_id_length);
}

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
	if (nhacp_o_flags & NHACP_O_DIRECTORY) {
		*fileio_o_flagsp |= FILEIO_O_DIRECTORY;
	} else {
		*fileio_o_flagsp |= FILEIO_O_REGULAR;
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

	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] nhacp_o_flags 0x%04x -> fileio_o_flags 0x%08x",
	    conn_name(ctx->stext.conn), nhacp_o_flags, fileio_o_flags);

	error = stext_file_open(&ctx->stext,
	    (const char *)ctx->request.storage_open.url_string,
	    ctx->request.storage_open.req_slot, &attrs, fileio_o_flags, &f);

	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		assert(f != NULL);

		struct nhacp_file_private *fp = stext_file_private(f);
		assert(fp != NULL);

		fp->is_directory = attrs.is_directory;
		fp->is_writable = attrs.is_writable;

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

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
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

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
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

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
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
		return;
	}
	if (blklen != save_blklen) {
		/* Partial read across EOF - zero-pad the result. */
		assert(save_blklen > blklen);
		memset(&ctx->reply.data_buffer.data[blklen], 0,
		    save_blklen - blklen);
	}
	nhacp_send_data_buffer(ctx, save_blklen);
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

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
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

	int error = stext_file_pwrite(f, ctx->request.storage_put_block.data,
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
	time_t now = time(NULL);

	if (now == (time_t)-1) {
		log_error("[%s] unable to get current time: %s",
		    conn_name(ctx->stext.conn), strerror(errno));
	}
	nhacp_time_from_unix(now, &ctx->reply.date_time.date_time);
	nhacp_send_reply(ctx, NHACP_RESP_DATE_TIME,
	    sizeof(ctx->reply.date_time));
}

/*
 * nhacp_req_file_close --
 *	Handle the FILE-CLOSE request.
 */
static void
nhacp_req_file_close(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.file_close.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn),
		    ctx->request.file_close.slot);
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

/*
 * nhacp_req_file_read --
 *	Handle the FILE-READ request.
 */
static void
nhacp_req_file_read(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.file_read.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.file_read.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
		return;
	}

	uint16_t flags = nabu_get_uint16(ctx->request.file_read.flags);
	uint16_t length = nabu_get_uint16(ctx->request.file_read.length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u flags 0x%04x length %u",
	    conn_name(ctx->stext.conn), ctx->request.file_read.slot,
	    flags, length);

	if (length > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_GET)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	if (flags != 0) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	int error = stext_file_read(f, ctx->reply.data_buffer.data, &length);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_data_buffer(ctx, length);
	}
}

/*
 * nhacp_req_file_write --
 *	Handle the FILE-WRITE request.
 */
static void
nhacp_req_file_write(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_put.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.file_write.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
		return;
	}

	uint16_t flags = nabu_get_uint16(ctx->request.file_write.flags);
	uint16_t length = nabu_get_uint16(ctx->request.file_write.length);

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u flags 0x%04x length %u",
	    conn_name(ctx->stext.conn), ctx->request.file_write.slot,
	    flags, length);

	if (length > nhacp_max_payload(ctx, NHACP_REQ_STORAGE_PUT)) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	if (flags != 0) {
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	int error = stext_file_write(f, ctx->request.file_write.data, length);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_ok(ctx);
	}
}

/*
 * nhacp_req_file_seek --
 *	Handle the FILE-SEEK request.
 */
static void
nhacp_req_file_seek(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.storage_put.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.file_seek.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	if (nhacp_file_is_directory(f)) {
		nhacp_send_error(ctx, NHACP_EISDIR);
		return;
	}

	int32_t offset =
	    (int32_t)nabu_get_uint32(ctx->request.file_seek.offset);
	int whence;

	switch (ctx->request.file_seek.whence) {
	case NHACP_SEEK_SET:	whence = SEEK_SET;	break;
	case NHACP_SEEK_CUR:	whence = SEEK_CUR;	break;
	case NHACP_SEEK_END:	whence = SEEK_END;	break;
	default:
		log_info("[%s] Bad whence value from client: %u",
		    conn_name(ctx->stext.conn), ctx->request.file_seek.whence);
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	log_debug(LOG_SUBSYS_NHACP, "[%s] slot %u whence %d offset %d",
	    conn_name(ctx->stext.conn), ctx->request.file_write.slot,
	    ctx->request.file_seek.whence, offset);

	int error = stext_file_seek(f, &offset, whence);
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_uint32(ctx, offset);
	}
}

/*
 * nhacp_req_list_dir --
 *	Handle the LIST-DIR request.
 */
static void
nhacp_req_list_dir(struct nhacp_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	struct stext_file *f;
	uint16_t nhacp_err = NHACP_EIO;
	char *path;
	glob_t g;

	f = stext_file_find(&ctx->stext, ctx->request.list_dir.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.list_dir.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	struct nhacp_file_private *fp = stext_file_private(f);

	if (! fp->is_directory) {
		nhacp_send_error(ctx, NHACP_ENOTDIR);
		return;
	}

	const char *location = stext_file_location(f);
	if (! fileio_location_is_local(location, strlen(location))) {
		nhacp_send_error(ctx, NHACP_EIO);
		return;
	}

	/* Clear out any previous file list. */
	nhacp_file_free_file_list(fp);

	ctx->request.list_dir.pattern[
	    ctx->request.list_dir.pattern_length] = '\0';

	/* Sanitize the pattern. */
	if (strchr((char *)ctx->request.list_dir.pattern, '/') != NULL) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Pattern '%s' contains path separator.",
		    conn_name(conn), (char *)ctx->request.list_dir.pattern);
		nhacp_send_error(ctx, NHACP_EINVAL);
		return;
	}

	memset(&g, 0, sizeof(g));

	if (asprintf(&path, "%s/%s", location,
		     (char *)ctx->request.list_dir.pattern) < 0) {
		log_error("[%s] Unable to allocate memory for glob pattern.",
		    conn_name(conn));
		nhacp_send_error(ctx, NHACP_ENOMEM);
		return;
	}

	log_debug(LOG_SUBSYS_NHACP, "[%s] Pattern for glob: %s",
	    conn_name(conn), path);

	int globret = glob(path, 0, NULL, &g);
	if (globret != 0) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] glob() returned %d.",
		    conn_name(conn), globret);
		nhacp_err = NHACP_EIO;
		goto bad;
	}
	log_debug(LOG_SUBSYS_NHACP, "[%s] glob() returned %zd matches.",
	    conn_name(conn), (size_t)g.gl_pathc);

	for (int i = 0; i < g.gl_pathc; i++) {
		struct fileio_attrs attrs;
		struct nhacp_file_list_entry *e;
		const char *fname;
		size_t fnamelen;

		if (! fileio_getattr_location(g.gl_pathv[i], 0, NULL, &attrs)) {
			log_error("[%s] Unable to get attrs for '%s': %s",
			    conn_name(conn), g.gl_pathv[i], strerror(errno));
			continue;
		}

		fname = strrchr(g.gl_pathv[i], '/');
		if (fname != NULL) {
			fname++;
		} else {
			fname = g.gl_pathv[i];
		}
		fnamelen = strlen(fname);
		if (fnamelen > 255) {
			fnamelen = 255;
		}

		e = nhacp_file_list_entry_alloc(fnamelen);
		if (e == NULL) {
			log_error("[%s] Failed to allocate file list entry.",
			    conn_name(conn));
			nhacp_err = NHACP_ENOMEM;
			goto bad;
		}

		nhacp_file_attrs_from_fileio(&attrs, &e->dir_entry->attrs);
		e->dir_entry->name_length = (uint8_t)fnamelen;
		memcpy(e->dir_entry->name, fname, fnamelen);
		STAILQ_INSERT_TAIL(&fp->file_list, e, link);
	}

	nhacp_send_ok(ctx);
 out:
	globfree(&g);
	return;

 bad:
	nhacp_send_error(ctx, nhacp_err);
	goto out;
}

/*
 * nhacp_req_get_dir_entry --
 *	Handle the GET-DIR-ENTRY request.
 */
static void
nhacp_req_get_dir_entry(struct nhacp_context *ctx)
{
	struct stext_file *f;

	f = stext_file_find(&ctx->stext, ctx->request.list_dir.slot);
	if (f == NULL) {
		log_debug(LOG_SUBSYS_NHACP, "[%s] No file for slot %u.",
		    conn_name(ctx->stext.conn), ctx->request.list_dir.slot);
		nhacp_send_error(ctx, NHACP_EBADF);
		return;
	}

	struct nhacp_file_private *fp = stext_file_private(f);

	if (! fp->is_directory) {
		nhacp_send_error(ctx, NHACP_ENOTDIR);
		return;
	}

	struct nhacp_file_list_entry *e = STAILQ_FIRST(&fp->file_list);
	if (e == NULL) {
		nhacp_send_ok(ctx);
		return;
	}

	/*
	 * The directory entry is all ready to go; just truncate the
	 * name to whatever the client is willing to accept.
	 */
	STAILQ_REMOVE_HEAD(&fp->file_list, link);
	if (e->dir_entry->name_length >
	    ctx->request.get_dir_entry.max_name_length) {
		e->dir_entry->name_length =
		    ctx->request.get_dir_entry.max_name_length;
	}
	memcpy(&ctx->reply.dir_entry, e->dir_entry,
	    sizeof(ctx->reply.dir_entry) + e->dir_entry->name_length);
	nhacp_send_reply(ctx, NHACP_RESP_DIR_ENTRY,
	    sizeof(ctx->reply.dir_entry) + e->dir_entry->name_length);
	nhacp_file_list_entry_free(e);
}

/*
 * nhacp_req_remove --
 *	Handle the REMOVE request.
 */
static void
nhacp_req_remove(struct nhacp_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	char *name;
	uint8_t namelen;
	int error = 0;

	namelen = ctx->request.remove.url_length;
	name = (char *)ctx->request.remove.url_string;
	name[namelen] = '\0';

	char *path =
	    fileio_resolve_path(name, conn->file_root, FILEIO_O_LOCAL_ROOT);
	if (path != NULL) {
		if (unlink(path) < 0) {
			error = errno;
			log_info("[%s] unlink(%s) failed: %s",
			    conn_name(conn), path, strerror(error));
		}
		free(path);
	} else {
		error = errno;
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unable to resolve path: %s", conn_name(conn), name);
	}

	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_ok(ctx);
	}
}

/*
 * nhacp_req_rename --
 *	Handle the RENAME request.
 */
static void
nhacp_req_rename(struct nhacp_context *ctx)
{
	struct nabu_connection *conn = ctx->stext.conn;
	char *old_name, *new_name;
	char *src_path = NULL, *dst_path = NULL;
	uint8_t old_namelen, new_namelen;
	int error = 0;
	uint8_t *bp;

	bp = ctx->request.rename.names;

	old_namelen = *bp++;
	old_name = (char *)bp;
	bp += old_namelen;

	new_namelen = *bp++;
	new_name = (char *)bp;

	old_name[old_namelen] = '\0';
	new_name[new_namelen] = '\0';

	src_path = fileio_resolve_path(old_name, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	if (src_path == NULL) {
		error = errno;
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unable to resolve src_path: %s", conn_name(conn),
		    old_name);
		goto out;
	}
	dst_path = fileio_resolve_path(new_name, conn->file_root,
	    FILEIO_O_LOCAL_ROOT);
	if (dst_path == NULL) {
		error = errno;
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Unable to resolve dst_path: %s", conn_name(conn),
		    old_name);
		goto out;
	}

	if (rename(src_path, dst_path) < 0) {
		error = errno;
		log_info("[%s] rename(%s, %s) failed: %s",
		    conn_name(conn), src_path, dst_path, strerror(error));
	}

 out:
	if (src_path != NULL) {
		free(src_path);
	}
	if (dst_path != NULL) {
		free(dst_path);
	}
	if (error != 0) {
		nhacp_send_error(ctx, nhacp_error_from_unix(error));
	} else {
		nhacp_send_ok(ctx);
	}
}

#define	HANDLER_ENTRY(v, d, n, mpv)					\
	[(v)] = {							\
		.handler    = nhacp_req_ ## n ,				\
		.debug_desc = d ,					\
		.min_reqlen = sizeof(struct nhacp_request_ ## n ),	\
		.min_version = (mpv),					\
	}

#define	ENTRY_0_0(v, n)		HANDLER_ENTRY(v, #v, n, NHACP_VERS_0_0)
#define	ENTRY_0_1(v, n)		HANDLER_ENTRY(v, #v, n, NHACP_VERS_0_1)

static const struct {
	void		(*handler)(struct nhacp_context *);
	const char	*debug_desc;
	ssize_t		min_reqlen;
	uint16_t	min_version;
} nhacp_request_types[] = {
	ENTRY_0_1(NHACP_REQ_HELLO,             hello),
	ENTRY_0_0(NHACP_REQ_STORAGE_OPEN,      storage_open),
	ENTRY_0_0(NHACP_REQ_STORAGE_GET,       storage_get),
	ENTRY_0_0(NHACP_REQ_STORAGE_PUT,       storage_put),
	ENTRY_0_0(NHACP_REQ_GET_DATE_TIME,     get_date_time),
	ENTRY_0_0(NHACP_REQ_FILE_CLOSE,        file_close),
	ENTRY_0_1(NHACP_REQ_GET_ERROR_DETAILS, get_error_details),
	ENTRY_0_1(NHACP_REQ_STORAGE_GET_BLOCK, storage_get_block),
	ENTRY_0_1(NHACP_REQ_STORAGE_PUT_BLOCK, storage_put_block),
	ENTRY_0_1(NHACP_REQ_FILE_READ,         file_read),
	ENTRY_0_1(NHACP_REQ_FILE_WRITE,        file_write),
	ENTRY_0_1(NHACP_REQ_FILE_SEEK,         file_seek),
	ENTRY_0_1(NHACP_REQ_LIST_DIR,          list_dir),
	ENTRY_0_1(NHACP_REQ_GET_DIR_ENTRY,     get_dir_entry),
	ENTRY_0_1(NHACP_REQ_REMOVE,            remove),
	ENTRY_0_1(NHACP_REQ_RENAME,            rename),
};
static const unsigned int nhacp_request_type_count =
    sizeof(nhacp_request_types) / sizeof(nhacp_request_types[0]);

#undef ENTRY_0_0
#undef ENTRY_0_1
#undef HANDLER_ENTRY

/*
 * nhacp_request_check --
 *	Validates the incoming request.
 */
static bool
nhacp_request_check(struct nhacp_context *ctx, uint16_t length)
{
	struct nabu_connection *conn = ctx->stext.conn;
	uint8_t req = ctx->request.generic.type;
	uint16_t options, min_reqlen, version;

	/* Max message length has already been checked. */
	assert(length <= NHACP_MAX_MESSAGELEN);

	switch (req) {
	case NHACP_REQ_GOODBYE:		/* same as END-PROTOCOL in 0.0 */
		min_reqlen = sizeof(struct nhacp_request_goodbye);
		break;

	default:
		if (req >= nhacp_request_type_count ||
		    nhacp_request_types[req].handler == NULL) {
			log_error("[%s] Unknown NHACP request: 0x%02x",
			    conn_name(conn), ctx->request.generic.type);
			return false;
		}
		min_reqlen = nhacp_request_types[req].min_reqlen;
		if (ctx->request.generic.type == NHACP_REQ_HELLO) {
			version = nabu_get_uint16(ctx->request.hello.version);
		} else {
			version = ctx->nhacp_version;
		}
		if (version < nhacp_request_types[req].min_version) {
			log_error("[%s] NHACP version (%u.%u) less than "
			    "minimum required (%u.%u) for %s.", conn_name(conn),
			    NHACP_VERS_MAJOR(ctx->nhacp_version),
			    NHACP_VERS_MINOR(ctx->nhacp_version),
			    NHACP_VERS_MAJOR(nhacp_request_types[
							req].min_version),
			    NHACP_VERS_MINOR(nhacp_request_types[
							req].min_version),
			    nhacp_request_types[req].debug_desc);
			return false;
		}
		break;
	}

	if (length < min_reqlen) {
		log_error("[%s] Runt NHACP request: %u < %u",
		    conn_name(conn), length, min_reqlen);
		return false;
	}

	/*
	 * If we're establishing a new NHACP session, get the options
	 * directly from the HELLO message.
	 */
	if (ctx->request.generic.type == NHACP_REQ_HELLO) {
		options = nabu_get_uint16(ctx->request.hello.options);
	} else {
		options = ctx->nhacp_options;
	}

	if (options & NHACP_OPTION_CRC8) {
		uint8_t *crc_ptr = nhacp_crc_ptr(ctx, options);

		if (*crc_ptr == 0) {
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] Client omitted CRC-8 on this request.",
			    conn_name(ctx->stext.conn));
		} else {
			/*
			 * The length doesn't include the size of the
			 * length field, but the CRC computation does.
			 */
			size_t crc_checklen =
			    length + sizeof(ctx->request.length);
			uint8_t crc = crc8_wcdma_init();
			crc = crc8_wcdma_update(&ctx->session_id, 1, crc);
			crc = crc8_wcdma_update(&ctx->request,
			    crc_checklen, crc);
			crc = crc8_wcdma_fini(crc);

			if (crc != 0) {
				/*
				 * Compute it again without the CRC byte
				 * so we can report computed vs. expected.
				 */
				crc = crc8_wcdma_init();
				crc = crc8_wcdma_update(&ctx->session_id, 1,
				    crc);
				crc = crc8_wcdma_update(&ctx->request,
				    crc_checklen - 1, crc);
				crc = crc8_wcdma_fini(crc);
				log_error("[%s] CRC-8 failure; "
				    "computed 0x%02x != received 0x%02x",
				    conn_name(ctx->stext.conn), crc, *crc_ptr);
				return false;
			} else {
				log_debug(LOG_SUBSYS_NHACP, "[%s] CRC-8 OK.",
				    conn_name(ctx->stext.conn));
			}
		}
	}

	/*
	 * All requests other than HELLO must be associated with an
	 * established NHACP session.
	 */
	if (ctx->request.generic.type != NHACP_REQ_HELLO && !ctx->linked) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] No session for session ID %u.",
		    conn_name(conn), ctx->session_id);
		/*
		 * ...but we don't send errors back for GOODBYE.
		 */
		if (ctx->request.generic.type != NHACP_REQ_GOODBYE) {
			nhacp_send_error(ctx, NHACP_ESRCH);
		}
		return false;
	}

	return true;
}

/*
 * nhacp_process_request --
 *	Invoke the handler for the specified request.
 */
static inline void
nhacp_process_request(struct nhacp_context *ctx)
{
	log_debug(LOG_SUBSYS_NHACP, "[%s] Got %s.", conn_name(ctx->stext.conn),
	    nhacp_request_types[ctx->request.generic.type].debug_desc);
	(*nhacp_request_types[ctx->request.generic.type].handler)(ctx);
}

/*
 * nhacp_start_0_0 --
 *	Enter NHACP-0.0 mode on this connection.
 */
static bool
nhacp_start_0_0(struct nabu_connection *conn)
{
	struct nhacp_context *ctx;
	extern char nabud_version[];
	uint16_t reqlen;

	/*
	 * Don't allow intermixing of 0.0 with 0.1-and-later.
	 */
	if (! LIST_EMPTY(&conn->nhacp_sessions)) {
		log_error("[%s] NHACP-0.0 start requested while "
		    "NHACP sessions are already established.",
		    conn_name(conn));
		return false;
	}

	/*
	 * If we failed to allocate a context, just don't send
	 * a reply -- act as if this were an unrecognized message.
	 */
	if ((ctx = nhacp_context_alloc(conn, NHACP_SESSION_SYSTEM)) == NULL) {
		log_error("[%s] Failed to allocate NHACP context.",
		    conn_name(conn));
		return true;
	}
	ctx->nhacp_version = NHACP_VERS_0_0;
	ctx->nhacp_options = 0;

	/*
	 * Send a NHACP-STARTED response.  We know there's room at the end
	 * for a NUL terminator.
	 */
	nabu_set_uint16(ctx->reply.nhacp_started_0_0.version,
	    NABUD_NHACP_VERSION);
	snprintf((char *)ctx->reply.nhacp_started_0_0.adapter_id, 256,
	    "%s-%s", getprogname(), nabud_version);
	ctx->reply.nhacp_started_0_0.adapter_id_length =
	    (uint8_t)strlen((char *)ctx->reply.nhacp_started_0_0.adapter_id);
	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] Sending proto version: 0x%04x server version: %s",
	    conn_name(conn), NABUD_NHACP_VERSION,
	    (char *)ctx->reply.nhacp_started_0_0.adapter_id);
	nhacp_send_reply(ctx, NHACP_RESP_NHACP_STARTED_0_0,
	    sizeof(ctx->reply.nhacp_started_0_0) +
	    ctx->reply.nhacp_started_0_0.adapter_id_length);

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

		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Receiving %u byte request.",
		    conn_name(conn), reqlen);

		/* Ok, receive the message. */
		if (! conn_recv(conn, &ctx->request.max_request, reqlen)) {
			if (! conn_check_state(conn)) {
				/* Error already logged. */
				break;
			}
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] conn_recv() %u bytes failed, "
			    "continuing event loop.", conn_name(conn), reqlen);
			continue;
		}

		/*
		 * Check for END-PROTOCOL before we do anything else.
		 * There's no payload and no reply -- we just get out.
		 */
		if (ctx->request.generic.type == NHACP_REQ_END_PROTOCOL_0_0) {
			log_debug(LOG_SUBSYS_NHACP,
			    "[%s] Got NHACP_REQ_END_PROTOCOL.",
			    conn_name(conn));
			break;
		}

		/*
		 * Check that the client has sent a valid request.
		 */
		if (! nhacp_request_check(ctx, reqlen)) {
			/*
			 * Error already logged.  Just skip the
			 * packet and continue.
			 */
			continue;
		}

		/* Everything checks out -- process the request. */
		nhacp_process_request(ctx);
	}

	log_info("[%s] Exiting NHACP mode.", conn_name(conn));
	nhacp_context_free(ctx);
	return true;
}

/*
 * nhacp_request --
 *	Handle an NHACP request.
 */
bool
nhacp_request(struct nabu_connection *conn, uint8_t msg)
{
	struct nhacp_context *ctx;
	uint16_t reqlen;
	uint8_t session_id;

	switch (msg) {
	case NABU_MSG_START_NHACP_0_0:
		/* This is a request to enter NHACP 0.0 mode. */
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Got NABU_MSG_START_NHACP_0_0.", conn_name(conn));
		return nhacp_start_0_0(conn);

	case NABU_MSG_NHACP_REQUEST:
		/* This is an NHACP >= 0.1 request. */
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Got NABU_MSG_NHACP_REQUEST.", conn_name(conn));
		break;

	default:
		/* Not an NHACP message. */
		return false;
	}

	conn_start_watchdog(conn, 1);

	/* Get the session ID. */
	if (! conn_recv_byte(conn, &session_id)) {
		if (! conn_check_state(conn)) {
			/* Error already logged. */
			return true;
		}
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] conn_recv_byte() failed, returning.",
		    conn_name(conn));
		return true;
	}

	/* Look up the context associated with this session ID. */
	ctx = nhacp_context_lookup(conn, session_id);
	if (ctx == NULL) {
		/*
		 * No context found; allocate a new context in case
		 * a new session is being established.
		 */
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Session %u not found; allocating a new one.",
		    conn_name(conn), session_id);
		ctx = nhacp_context_alloc(conn, session_id);
		if (ctx == NULL) {
			log_error("[%s] Failed to allocate context.",
			    conn_name(conn));
			return true;
		}
	} else {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Found context for session ID %u.",
		    conn_name(conn), session_id);
	}

	/* Get the frame length. */
	if (! conn_recv(conn, &ctx->request.length,
			sizeof(ctx->request.length))) {
		if (! conn_check_state(conn)) {
			/* Error already logged. */
			goto out;
		}
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] conn_recv() failed, returning.",
		    conn_name(conn));
		goto out;
	}

	reqlen = nabu_get_uint16(ctx->request.length);

	if (! nhacp_reqlen_ok(ctx, reqlen)) {
		log_error("[%s] Bogus request length: 0x%04x.",
		    conn_name(conn), reqlen);
		goto out;
	}

	log_debug(LOG_SUBSYS_NHACP,
	    "[%s] Receiving %u byte request.", conn_name(conn), reqlen);

	/* Ok, receive the message. */
	if (! conn_recv(conn, &ctx->request.max_request, reqlen)) {
		if (! conn_check_state(conn)) {
			/* Error already logged. */
			goto out;
		}
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] conn_recv() %u bytes failed.", conn_name(conn),
		    reqlen);
		goto out;
	}

	/*
	 * Check that the client has sent a valid request.
	 */
	if (! nhacp_request_check(ctx, reqlen)) {
		/*
		 * Error already logged.  Just skip the
		 * packet and continue.
		 */
		goto out;
	}

	/*
	 * Everything checks out -- process the request.  GOODBYE is
	 * handled as a special case.
	 */
	if (ctx->request.generic.type == NHACP_REQ_GOODBYE) {
		if (ctx->session_id == NHACP_SESSION_SYSTEM) {
			log_info("[%s] Ending all NHACP sessions.",
			    conn_name(conn));
			nhacp_conn_reset(conn, NULL);
		} else {
			log_info("[%s] Ending NHACP session %u.",
			    conn_name(conn), ctx->session_id);
			nhacp_context_free(ctx);
		}
		return true;
	}
	nhacp_process_request(ctx);
 out:
	if (! ctx->linked) {
		log_debug(LOG_SUBSYS_NHACP,
		    "[%s] Freeing unlinked context.", conn_name(conn));
		nhacp_context_free(ctx);
	}
	return true;
}

/*
 * nhacp_conn_fini --
 *	Tear down any lingering NHACP state for a connection.
 */
void
nhacp_conn_fini(struct nabu_connection *conn)
{
	nhacp_conn_reset(conn, NULL);
}
