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

struct stext_file {
	LIST_ENTRY(stext_file) link;
	const struct stext_fileops *ops;
	uint8_t		slot;
	bool		linked;

	union {
		struct {
			struct fileio	*fileio;
		} fileio;
		struct {
			uint8_t		*data;
			size_t		length;
			uint32_t	cursor;
		} shadow;
	};
};

struct stext_fileops {
	off_t	max_length;
	int	(*file_read)(struct stext_file *, void *, uint16_t *);
	int	(*file_write)(struct stext_file *, const void *, uint16_t);
	int	(*file_pread)(struct stext_file *, void *, uint32_t,
		    uint16_t *);
	int	(*file_pwrite)(struct stext_file *, const void *, uint32_t,
		    uint16_t);
	off_t	(*file_seek)(struct stext_file *, off_t, int);
	int	(*file_truncate)(struct stext_file *, uint32_t);
	void	(*file_close)(struct stext_file *);
};

/*
 * stext_file_insert --
 *	Insert a file into the list, allocating a slot number if
 *	necessary.  This always succeeds, and returns the old
 *	file object that needs to be freed if there's a collision.
 */
static int
stext_file_insert(struct stext_context *ctx, struct stext_file *f,
    uint8_t reqslot)
{
	struct stext_file *lf, *prevf = NULL;
	uint8_t slot;

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
				return EMFILE;
			}
			prevf = lf;
		}
		f->slot = slot;
		goto insert_after;
	}

	/*
	 * We're being asked to allocate a specific slot.  If we find
	 * another file there, fail the request.
	 */
	slot = f->slot = reqslot;
	LIST_FOREACH(lf, &ctx->files, link) {
		if (slot > lf->slot) {
			prevf = lf;
			continue;
		}
		if (slot == lf->slot) {
			/* This slot is in-use. */
			return EBUSY;
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
	f->linked = true;
	return 0;
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
		stext_file_close(f);
	}
}

/*****************************************************************************
 * File ops for live read/write files.
 *****************************************************************************/

static int
stext_fileop_read_fileio(struct stext_file *f, void *vbuf, uint16_t *lengthp)
{
	uint8_t *buf = vbuf;
	size_t resid = *lengthp;
	ssize_t actual;

	while (resid != 0) {
		actual = fileio_read(f->fileio.fileio, buf, resid);
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
		resid -= actual;
	}
	*lengthp -= resid;
	return 0;
}

static int
stext_fileop_write_fileio(struct stext_file *f, const void *vbuf,
    uint16_t length)
{
	const uint8_t *buf = vbuf;
	size_t resid = length;
	ssize_t actual;

	while (resid != 0) {
		actual = fileio_write(f->fileio.fileio, buf, resid);
		if (actual <= 0) {
			if (actual < 0 && errno == EINTR) {
				continue;
			}
			return errno;
		}
		buf += actual;
		resid -= actual;
	}
	return 0;
}

static int
stext_fileop_pread_fileio(struct stext_file *f, void *vbuf, uint32_t offset,
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
stext_fileop_pwrite_fileio(struct stext_file *f, const void *vbuf,
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

static off_t
stext_fileop_seek_fileio(struct stext_file *f, off_t offset, int whence)
{
	return fileio_seek(f->fileio.fileio, offset, whence);
}

static int
stext_fileop_truncate_fileio(struct stext_file *f, uint32_t size)
{
	if (! fileio_truncate(f->fileio.fileio, size)) {
		return errno;
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

static const struct stext_fileops stext_fileops_fileio = {
	.max_length	= MAX_FILEIO_LENGTH,
	.file_read	= stext_fileop_read_fileio,
	.file_write	= stext_fileop_write_fileio,
	.file_pread	= stext_fileop_pread_fileio,
	.file_pwrite	= stext_fileop_pwrite_fileio,
	.file_seek	= stext_fileop_seek_fileio,
	.file_truncate	= stext_fileop_truncate_fileio,
	.file_close	= stext_fileop_close_fileio,
};

/*****************************************************************************
 * File ops for shadow buffered files.
 *****************************************************************************/

static int
stext_fileop_read_shadow(struct stext_file *f, void *vbuf, uint16_t *lengthp)
{
	uint32_t offset;
	int error;

	offset = (uint32_t)f->shadow.cursor;

	error = stext_file_pread(f, vbuf, offset, lengthp);
	if (error == 0) {
		f->shadow.cursor += *lengthp;
	}
	return error;
}

static int
stext_fileop_write_shadow(struct stext_file *f, const void *vbuf,
    uint16_t length)
{
	uint32_t offset = (uint32_t)f->shadow.cursor;
	int error;

	error = stext_file_pwrite(f, vbuf, offset, length);
	if (error == 0) {
		f->shadow.cursor += length;
	}
	return error;
}

static int
stext_fileop_pread_shadow(struct stext_file *f, void *vbuf, uint32_t offset,
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
stext_fileop_pwrite_shadow(struct stext_file *f, const void *vbuf,
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

static off_t
stext_fileop_seek_shadow(struct stext_file *f, off_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		if (offset < 0) {
			goto invalid;
		}
		f->shadow.cursor = offset;
		break;

	case SEEK_CUR:
		if (offset < 0 && -offset > f->shadow.cursor) {
			goto invalid;
		}
		f->shadow.cursor += offset;
		break;

	case SEEK_END:
		if (offset < 0 && -offset > f->shadow.length) {
			goto invalid;
		}
		f->shadow.cursor = f->shadow.length + offset;
		break;

	default:
	invalid:
		errno = EINVAL;
		return -1;
	}

	return f->shadow.cursor;
}

static int
stext_fileop_truncate_shadow(struct stext_file *f, uint32_t size)
{
	if (size <= f->shadow.length) {
		f->shadow.length = size;
		return 0;
	}

	uint8_t *newbuf = realloc(f->shadow.data, size);
	if (newbuf == NULL) {
		return ENOMEM;
	}
	memset(newbuf + f->shadow.length, 0, size - f->shadow.length);
	if (f->shadow.data != newbuf) {
		free(f->shadow.data);
		f->shadow.data = newbuf;
	}
	return 0;
}

static void
stext_fileop_close_shadow(struct stext_file *f)
{
	if (f->shadow.data != NULL) {
		free(f->shadow.data);
	}
}

static const struct stext_fileops stext_fileops_shadow = {
	.max_length	= MAX_SHADOW_LENGTH,
	.file_read	= stext_fileop_read_shadow,
	.file_write	= stext_fileop_write_shadow,
	.file_pread	= stext_fileop_pread_shadow,
	.file_pwrite	= stext_fileop_pwrite_shadow,
	.file_seek	= stext_fileop_seek_shadow,
	.file_truncate	= stext_fileop_truncate_shadow,
	.file_close	= stext_fileop_close_shadow,
};

/*
 * stext_open_file --
 *	Open a file.
 */
int
stext_file_open(struct stext_context *ctx, const char *filename,
    uint8_t reqslot, struct fileio_attrs *attrs, struct stext_file **outfp)
{
	struct stext_file *f = NULL;
	struct fileio *fileio = NULL;
	bool need_shadow = false;
	int error = 0;

	*outfp = NULL;

	f = calloc(1, sizeof(*f));
	if (f == NULL) {
		log_error("[%s] Unable to allocate file object for '%s'",
		    conn_name(ctx->conn), filename);
		error = ENOMEM;
		goto out;
	}

	log_debug("[%s] Opening '%s'", conn_name(ctx->conn), filename);
	fileio = fileio_open(filename,
	    FILEIO_O_CREAT | FILEIO_O_LOCAL_ROOT | FILEIO_O_RDWR,
	    ctx->conn->file_root, attrs);
	if (fileio == NULL) {
		/*
		 * Try opening read-only.  If that succeeds, then we just
		 * allocate a shadow file.
		 */
		fileio = fileio_open(filename,
		    FILEIO_O_LOCAL_ROOT | FILEIO_O_RDONLY,
		    ctx->conn->file_root, attrs);
		if (fileio != NULL) {
			log_debug("[%s] Need R/W shadow buffer for '%s'",
			    conn_name(ctx->conn), filename);
			need_shadow = true;
		}
	}
	if (fileio == NULL) {
		log_error("[%s] Unable to open file '%s': %s",
		    conn_name(ctx->conn), filename, strerror(errno));
		error = ENOENT;
		goto out;
	}

	/* Opening directories is not allowed. */
	if (attrs->is_directory) {
		log_error("[%s] '%s': Opening directories is not permitted.",
		    conn_name(ctx->conn), fileio_location(fileio));
		error = EINVAL;
		goto out;
	}

	/*
	 * If the underlying file object is not seekable, then we need
	 * to allocate a shadow file, because the wire protocol only has
	 * positional I/O.
	 */
	if (! attrs->is_seekable) {
		log_debug("[%s] Need seekable shadow buffer for '%s'",
		    conn_name(ctx->conn), fileio_location(fileio));
		need_shadow = true;
	}

	if (need_shadow) {
		if (attrs->size > MAX_SHADOW_LENGTH) {
			log_debug("[%s] '%s' exceeds maximum shadow length %u.",
			    conn_name(ctx->conn),
			    fileio_location(fileio),
			    MAX_SHADOW_LENGTH);
			error = EFBIG;
			goto out;
		}

		f->shadow.data = fileio_load_file(fileio, attrs,
		    0 /*extra*/, 0 /*maxsize XXX*/, &f->shadow.length);
		f->ops = &stext_fileops_shadow;
	} else {
		if (attrs->size > MAX_FILEIO_LENGTH) {
			log_debug("[%s] '%s' exceeds maximum file size %u.",
			    conn_name(ctx->conn),
			    fileio_location(f->fileio.fileio),
			    MAX_FILEIO_LENGTH);
			error = EFBIG;
			goto out;
		}
		f->fileio.fileio = fileio;
		fileio = NULL;		/* file owns it now */
		f->ops = &stext_fileops_fileio;
	}

	error = stext_file_insert(ctx, f, reqslot);
	if (error != 0) {
		log_error("[%s] Unable to insert %s at requsted slot %u: %s.",
		    conn_name(ctx->conn), filename, reqslot, strerror(error));
		goto out;
	}
	*outfp = f;
	f = NULL;

 out:
	if (fileio != NULL) {
		fileio_close(fileio);
	}
	if (f != NULL) {
		stext_file_close(f);
	}
	assert((error == 0 && *outfp != NULL) ||
	       (error != 0 && *outfp == NULL));
	return error;
}

/*
 * stext_file_slot --
 *	Return the storage slot occupied by a file.
 */
uint8_t
stext_file_slot(struct stext_file *f)
{
	assert(f->linked == true);
	return f->slot;
}

/*
 * stext_file_close --
 *	Close a file.  Must be unlinked from the stext_context.
 */
void
stext_file_close(struct stext_file *f)
{
	if (f->ops != NULL) {
		(*f->ops->file_close)(f);
	}
	if (f->linked) {
		LIST_REMOVE(f, link);
	}
	free(f);
}

/*
 * stext_file_read --
 *	File read.
 */
int
stext_file_read(struct stext_file *f, void *vbuf, uint16_t *lengthp)
{
	return (*f->ops->file_read)(f, vbuf, lengthp);
}

/*
 * stext_file_write --
 *	File write.
 */
int
stext_file_write(struct stext_file *f, const void *vbuf, uint16_t length)
{
	return (*f->ops->file_write)(f, vbuf, length);
}

/*
 * stext_file_pread --
 *	Positional file read.
 */
int
stext_file_pread(struct stext_file *f, void *vbuf, uint32_t offset,
    uint16_t *lengthp)
{
	return (*f->ops->file_pread)(f, vbuf, offset, lengthp);
}

/*
 * stext_file_pwrite --
 *	Positional file write.
 */
int
stext_file_pwrite(struct stext_file *f, const void *vbuf, uint32_t offset,
    uint16_t length)
{
	return (*f->ops->file_pwrite)(f, vbuf, offset, length);
}

/*
 * stext_file_seek --
 *	Reposition the read/write cursor.
 */
int
stext_file_seek(struct stext_file *f, int32_t *offsetp, int whence)
{
	off_t ooff, noff;

	/* Get current position in case we have to unwind. */
	ooff = (*f->ops->file_seek)(f, 0, SEEK_CUR);
	if (ooff < 0) {
		return EIO;
	}

	/* Seek to the new position. */
	noff = (*f->ops->file_seek)(f, *offsetp, whence);
	if (noff < 0) {
		return EINVAL;
	}

	if (noff >= f->ops->max_length) {
		(*f->ops->file_seek)(f, ooff, SEEK_SET);
		return EFBIG;
	}

	*offsetp = (int32_t)noff;
	return 0;
}

/*
 * stext_file_truncate --
 *	Trucate a file to the specified size.
 */
int
stext_file_truncate(struct stext_file *f, uint32_t size)
{
	if (size > f->ops->max_length) {
		return EFBIG;
	}

	return (*f->ops->file_truncate)(f, size);
}
