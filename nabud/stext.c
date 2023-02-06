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
 * Common subroutines for storage extensions.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libnabud/fileio.h"
#include "libnabud/log.h"
#include "libnabud/missing.h"
#include "libnabud/nbsd_queue.h"

#include "conn.h"
#include "stext.h"

/* 1MB limit on shadow file length. */
#define	MAX_SHADOW_LENGTH	(1U * 1024 * 1024)

/* 32-bit limit on fileio file length (due to wire protocol). */
#define	MAX_FILEIO_LENGTH	UINT32_MAX

/*
 * stext_file_insert --
 *	Insert a file into the list, allocating a slot number if
 *	necessary.  This always succeeds, and returns the old
 *	file object that needs to be freed if there's a collision.
 */
bool
stext_file_insert(struct stext_context *ctx, struct stext_file *f,
    uint8_t reqslot, struct stext_file **oldfp)
{
	struct stext_file *lf, *prevf = NULL;
	uint8_t slot;

	*oldfp = NULL;

	if (reqslot == 0xff) {
		/*
		 * We're being asked to allocate a slot #.  Find the
		 * lowest slot number and use that.
		 */
		slot = 0;
		LIST_FOREACH(lf, &ctx->files, link) {
			assert(lf->slot != 0xff);
			assert(slot <= lf->slot);
			if (slot < lf->slot) {
				f->slot = slot;
				LIST_INSERT_BEFORE(lf, f, link);
				goto success;
			}
			slot = lf->slot + 1;
			if (slot == 0xff) {
				/* File table is full. */
				return false;
			}
			prevf = lf;
		}
		f->slot = slot;
		goto insert_after;
	}

	/*
	 * We're being asked to allocate a specific slot, possibly
	 * replacing another file.
	 */
	slot = f->slot = reqslot;
	LIST_FOREACH(lf, &ctx->files, link) {
		if (slot > lf->slot) {
			prevf = lf;
			continue;
		}
		if (slot == lf->slot) {
			LIST_REMOVE(lf, link);
			*oldfp = lf;
			goto insert_after;
		}
		if (slot < lf->slot) {
			LIST_INSERT_BEFORE(lf, f, link);
			goto success;
		}
	}
 insert_after:
	if (prevf != NULL) {
		LIST_INSERT_AFTER(prevf, f, link);
	} else {
		LIST_INSERT_HEAD(&ctx->files, f, link);
	}
 success:
	assert(f->slot != 0xff);
	assert((lf = LIST_NEXT(f, link)) == NULL || lf->slot > f->slot);
	return true;
}

struct stext_file *
stext_file_find(struct stext_context *ctx, uint8_t slot)
{
	struct stext_file *f;

	if (slot == 0xff) {
		return NULL;
	}

	LIST_FOREACH(f, &ctx->files, link) {
		/* The list is sorted. */
		if (f->slot > slot) {
			break;
		}
		if (f->slot == slot) {
			return f;
		}
	}
	return NULL;
}

void
stext_file_close(struct stext_file *f)
{
	if (f->ops != NULL) {
		(*f->ops->file_close)(f);
	}
	free(f);
}

/*
 * stext_context_init --
 *	Initlaize a storage extension context.
 */
void
stext_context_init(struct stext_context *ctx, struct nabu_connection *conn)
{
	LIST_INIT(&ctx->files);
	ctx->conn = conn;
}

/*
 * stext_context_fini --
 *	Close all files associated with this connection.
 */
void
stext_context_fini(struct stext_context *ctx)
{
	struct stext_file *f;

	while ((f = LIST_FIRST(&ctx->files)) != NULL) {
		log_debug("[%s] Freeing file at slot %u.", conn_name(ctx->conn),
		    f->slot);
		LIST_REMOVE(f, link);
		stext_file_close(f);
	}
}

/*****************************************************************************
 * File ops for live read/write files.
 *****************************************************************************/

static int
stext_fileop_read_fileio(struct stext_file *f, void *vbuf, uint32_t offset,
    uint16_t *lengthp)
{
	uint8_t *buf = vbuf;
	size_t resid = *lengthp;
	ssize_t actual;

	if (resid > MAX_FILEIO_LENGTH - offset) {
		resid = MAX_FILEIO_LENGTH - offset;
	}

	while (resid != 0) {
		actual = fileio_pread(f->fileio.fileio, buf, resid, offset);
		if (actual < 0) {
			if (errno == EINTR) {
				continue;
			}
			return errno;
		}
		if (actual == 0) {
			/* EOF. */
			break;
		}
		buf += actual;
		offset += actual;
		resid -= actual;
	}
	*lengthp -= resid;
	return 0;
}

static int
stext_fileop_write_fileio(struct stext_file *f, const void *vbuf,
    uint32_t offset, uint16_t length)
{
	const uint8_t *buf = vbuf;
	size_t resid = length;
	ssize_t actual;

	if (resid > MAX_FILEIO_LENGTH - offset) {
		return EFBIG;
	}

	while (resid != 0) {
		actual = fileio_pwrite(f->fileio.fileio, buf, resid, offset);
		if (actual <= 0) {
			if (actual < 0 && errno == EINTR) {
				continue;
			}
			return errno;
		}
		buf += actual;
		offset += actual;
		resid -= actual;
	}
	return 0;
}

static void
stext_fileop_close_fileio(struct stext_file *f)
{
	if (f->fileio.fileio != NULL) {
		fileio_close(f->fileio.fileio);
	}
}

const struct stext_fileops stext_fileops_fileio = {
	.file_read	= stext_fileop_read_fileio,
	.file_write	= stext_fileop_write_fileio,
	.file_close	= stext_fileop_close_fileio,
};

/*****************************************************************************
 * File ops for shadow buffered files.
 *****************************************************************************/

static int
stext_fileop_read_shadow(struct stext_file *f, void *vbuf, uint32_t offset,
    uint16_t *lengthp)
{
	uint16_t length = *lengthp;

	if (offset >= f->shadow.length) {
		length = 0;
	} else if (length > f->shadow.length - offset) {
		length = f->shadow.length - offset;
	}
	if (length != 0) {
		memcpy(vbuf, f->shadow.data + offset, length);
	}
	*lengthp = length;
	return 0;
}

static int
stext_fileop_write_shadow(struct stext_file *f, const void *vbuf,
    uint32_t offset, uint16_t length)
{
	if (length > MAX_SHADOW_LENGTH - offset) {
		return EFBIG;
	}

	if (offset + length > f->shadow.length) {
		uint8_t *newbuf = realloc(f->shadow.data, offset + length);
		if (newbuf == NULL) {
			return EIO;
		}
		memset(newbuf + f->shadow.length, 0,
		    offset + length - f->shadow.length);
		if (newbuf != f->shadow.data) {
			free(f->shadow.data);
			f->shadow.data = newbuf;
		}
		f->shadow.length = offset + length;
	}
	memcpy(f->shadow.data + offset, vbuf, length);
	return 0;
}

static void
stext_fileop_close_shadow(struct stext_file *f)
{
	if (f->shadow.data != NULL) {
		free(f->shadow.data);
	}
}

const struct stext_fileops stext_fileops_shadow = {
	.file_read	= stext_fileop_read_shadow,
	.file_write	= stext_fileop_write_shadow,
	.file_close	= stext_fileop_close_shadow,
};
