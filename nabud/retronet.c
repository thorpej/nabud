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
 * Support for NabuRetroNet features / extensions.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libnabud/fileio.h"
#include "libnabud/log.h"

#include "conn.h"
#include "retronet.h"

/*
 * rn_file_insert --
 *	Insert a file into the list, allocating a slot number if
 *	necessary.  This always succeeds, and returns the old
 *	file object that needs to be freed if there's a collision.
 */
static bool
rn_file_insert(struct nabu_connection *conn, struct rn_file *f,
    uint8_t reqslot, struct rn_file **oldfp)
{
	struct rn_file *lf, *prevf = NULL;
	uint8_t slot;

	*oldfp = NULL;

	if (reqslot == 0xff) {
		/*
		 * We're being asked to allocate a slot #.  Find the
		 * lowest slot number and use that.
		 */
		slot = 0;
		LIST_FOREACH(lf, &conn->rn_files, link) {
			assert(lf->slot != 0xff);
			assert(slot <= lf->slot);
			if (slot < lf->slot) {
				f->slot = slot;
				LIST_INSERT_BEFORE(lf, f, link);
				goto success;
			}
			slot = lf->slot + 1;
			if (slot == 0xff) {
				/*
				 * The connection is using 255 slots
				 * slots.  The protocol has no provision
				 * for failure, but this situation is
				 * absurd.  Instead, this implementation
				 * treats this situation as a failure
				 * and treats slot 255 as a dead file.
				 */
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
	LIST_FOREACH(lf, &conn->rn_files, link) {
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
		LIST_INSERT_HEAD(&conn->rn_files, f, link);
	}
 success:
	assert(f->slot != 0xff);
	assert((lf = LIST_NEXT(f, link)) == NULL || lf->slot > f->slot);
	return true;
}

static struct rn_file *
rn_file_find(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_file *f;

	if (slot == 0xff) {
		return NULL;
	}

	LIST_FOREACH(f, &conn->rn_files, link) {
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

static void
rn_file_free(struct rn_file *f)
{
	if (f->file != NULL) {
		fileio_close(f->file);
	}
	if (f->shadow_data != NULL) {
		free(f->shadow_data);
	}
	free(f);
}

/*
 * rn_file_closeall --
 *	Close all files associated with this connection.
 */
void
rn_file_closeall(struct nabu_connection *conn)
{
	struct rn_file *f;

	while ((f = LIST_FIRST(&conn->rn_files)) != NULL) {
		log_debug("[%s] Freeing file at slot %u.", conn_name(conn),
		    f->slot);
		LIST_REMOVE(f, link);
		rn_file_free(f);
	}
}

/*
 * rn_api_file_open --
 *	RetroNet API: Open a file.
 */
uint8_t
rn_api_file_open(struct nabu_connection *conn,
    const char *filename, uint16_t open_flags, uint8_t reqslot)
{
	struct rn_file *f = NULL, *of = NULL;
	struct fileio_attrs attrs;
	uint8_t slot = 0xff;
	bool need_shadow = false;
	int fileio_oflags, fileio_rwflags;

	f = calloc(1, sizeof(*f));
	if (f == NULL) {
		log_error("[%s] Unable to allocate RN file object for %s",
		    conn_name(conn), filename);
		goto out;
	}

	fileio_oflags = FILEIO_O_CREAT | FILEIO_O_LOCAL_ROOT;
	fileio_rwflags =
	    (open_flags & RN_FILE_OPEN_RW) ? FILEIO_O_RDWR : FILEIO_O_RDONLY;

	log_debug("[%s] Opening %s", conn_name(conn), filename);
	f->file = fileio_open(filename, fileio_oflags | fileio_rwflags,
	    conn->rn_file_root, &attrs);
	if (f->file == NULL && (open_flags & RN_FILE_OPEN_RW)) {
		/*
		 * Try opening read-only.  If that succeeds, then we just
		 * allocate a shadow file.
		 */
		f->file = fileio_open(filename,
		    fileio_oflags | FILEIO_O_RDONLY,
		    conn->rn_file_root, &attrs);
		if (f->file != NULL) {
			log_debug("[%s] Need R/W shadow file for %s",
			    conn_name(conn), filename);
			need_shadow = true;
		}
	}
	if (f->file == NULL) {
		log_error("[%s] Unable to open file %s: %s", conn_name(conn),
		    filename, strerror(errno));
		/*
		 * The RetroNet API has no provision for "opening a file
		 * failed".
		 */
		goto out;
	}

	/* Opening directories is not allowed. */
	if (attrs.is_directory) {
		log_error("[%s] %s: Opening directories is not permitted.",
		    conn_name(conn), fileio_location(f->file));
		goto out;
	}

	/*
	 * If the underlying file object is not seekable, then we need
	 * to allocate a shadow file, because the RetroNet API has only
	 * positional I/O.
	 */
	if (! attrs.is_seekable) {
		log_debug("[%s] Need seekable shadow file for %s",
		    conn_name(conn), fileio_location(f->file));
		need_shadow = true;
	}

	if (need_shadow) {
		f->shadow_data = fileio_load_file(f->file, &attrs,
		    0 /*extra*/, 0 /*maxsize XXX*/, &f->shadow_len);

		/* We're done with the file. */
		fileio_close(f->file);
		f->file = NULL;
	}

	if (! rn_file_insert(conn, f, reqslot, &of)) {
		log_error("[%s] Unable to insert %s at requsted slot %u.",
		    conn_name(conn), filename, reqslot);
		goto out;
	}
	slot = f->slot;
	f = NULL;

 out:
	if (f != NULL) {
		rn_file_free(f);
	}
	if (of != NULL) {
		rn_file_free(of);
	}
	return slot;
}

/*
 * rn_api_fh_close --
 *	RetroNet API: Close a file handle.
 */
void
rn_api_fh_close(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_file *f;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}
	log_debug("[%s] Freeing file at slot %d.", conn_name(conn), slot);
	LIST_REMOVE(f, link);
	rn_file_free(f);
}

/*
 * rn_api_fh_size --
 *	RetroNet API: Get the the size the file associated with a file handle.
 */
int32_t
rn_api_fh_size(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_file *f;
	int32_t filesize = -1;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return -1;
	}

	if (f->shadow_data != NULL) {
		filesize = (int32_t)f->shadow_len;
	} else if (f->file != NULL) {
		struct fileio_attrs attrs;

		if (! fileio_getattr(f->file, &attrs)) {
			log_error("[%s] slot %u: fileio_getattr(): %s",
			    conn_name(conn), slot, strerror(errno));
			filesize = -1;
		} else {
			filesize = (int32_t)attrs.size;
		}
	}
	log_debug("[%s] slot %u: file size: %zd.", conn_name(conn),
	    slot, (ssize_t)filesize);
	return filesize;
}

/*
 * rn_api_fh_read --
 *	RetroNet API: Read from a file.
 */
void
rn_api_fh_read(struct nabu_connection *conn,
    uint8_t slot, void *vbuf, uint32_t offset, uint16_t length)
{
	struct rn_file *f;
	uint8_t *buf = vbuf;

	/* Start with a buffer of zeros. */
	memset(buf, 0, length);

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->shadow_data != NULL) {
		if (offset >= f->shadow_len) {
			log_debug("[%s] slot %u: offset %u >= length %zu.",
			    conn_name(conn), slot, offset, f->shadow_len);
			return;
		}
		uint16_t copylen = length;
		if (f->shadow_len - offset > copylen) {
			copylen = f->shadow_len - offset;
		}
		log_debug("[%s] slot %u: Copying %zu bytes from shadow "
		    "offset %u.", conn_name(conn), slot, (size_t)copylen,
		    offset);
		memcpy(buf, &f->shadow_data[offset], copylen);
	} else if (f->file != NULL) {
		ssize_t actual;

		actual = fileio_pread(f->file, buf, length, offset);
		if (actual < 0) {
			log_error("[%s] slot %u: fileio_pread(%zu @ %u): %s",
			    conn_name(conn), slot, (size_t)length, offset,
			    strerror(errno));
		} else {
			log_debug("[%s] slot %u: fileio_pread(%zu @ %u) -> %zd",
			    conn_name(conn), slot, (size_t)length, offset,
			    actual);
		}
	}
}

/*
 * rn_api_fh_append --
 *	RetroNet API: Append to the end of a file.
 */
void
rn_api_fh_append(struct nabu_connection *conn,
    uint8_t slot, void *vbuf, uint16_t length)
{
	struct rn_file *f;
	uint8_t *buf = vbuf;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->shadow_data != NULL) {
		uint8_t *newdata = realloc(f->shadow_data,
		    f->shadow_len + length);
		if (newdata == NULL) {
			log_error("[%s] slot %u: unable to allocate %zu bytes"
			    "for append.", conn_name(conn), slot,
			    (size_t)length);
			return;
		}

		memcpy(&newdata[f->shadow_len], buf, length);
		if (f->shadow_data != newdata) {
			free(f->shadow_data);
			f->shadow_data = newdata;
		}
		f->shadow_len += length;
	} else if (f->file != NULL) {
		ssize_t actual;

		if (fileio_seek(f->file, 0, SEEK_END) < 0) {
			log_error("[%s] Failed to seek to end of file in "
			    "slot %u: %s", conn_name(conn), slot,
			    strerror(errno));
			return;
		}
		actual = fileio_write(f->file, buf, length);
		if (actual != (ssize_t)length) {
			log_error("[%s] slot %u: "
			    "fileio_write(%zu @ EOF) -> %zd%s%s",
			    conn_name(conn), slot, (size_t)length, actual,
			    actual == -1 ? " " : "",
			    actual == -1 ? strerror(errno) : "");
		}
	}
}

/*
 * rn_api_fh_replace --
 *	RetroNet API: Replace bytes within a file.
 *
 *	N.B. this also has the side-effect of extending, if necessary.
 */
void
rn_api_fh_replace(struct nabu_connection *conn,
    uint8_t slot, void *vbuf, uint32_t offset, uint16_t length)
{
	struct rn_file *f;
	uint8_t *buf = vbuf;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->shadow_data != NULL) {
		size_t newlen = offset + length;
		uint8_t *newdata;

		if (newlen > f->shadow_len) {
			newdata = realloc(f->shadow_data, newlen);
			if (newdata == NULL) {
				log_error("[%s] slot %u: unable to allocate "
				    "%zu bytes to extend.", conn_name(conn),
				    slot, f->shadow_len - newlen);

				/* Truncate the write. */
				length -= newlen - f->shadow_len;
				assert(offset + length == f->shadow_len);
			}
		} else {
			newdata = f->shadow_data;
			newlen = f->shadow_len;
		}

		if (offset > f->shadow_len) {
			memset(&newdata[f->shadow_len], 0,
			    offset - f->shadow_len);
		}
		memcpy(&newdata[offset], buf, length);
		if (f->shadow_data != newdata) {
			free(f->shadow_data);
			f->shadow_data = newdata;
		}
		f->shadow_len = newlen;
	} else if (f->file != NULL) {
		ssize_t actual;

		actual = fileio_pwrite(f->file, buf, length, offset);
		if (actual != (ssize_t)length) {
			log_error("[%s] slot %u: "
			    "fileio_write(%zu @ %u) -> %zd%s%s",
			    conn_name(conn), slot, (size_t)length, offset,
			    actual,
			    actual == -1 ? " " : "",
			    actual == -1 ? strerror(errno) : "");
		}
	}
}

/*
 * rn_api_fh_insert --
 *	RetroNet API: Insert bytes into a file.
 */
void
rn_api_fh_insert(struct nabu_connection *conn,
    uint8_t slot, void *vbuf, uint32_t offset, uint16_t length)
{
	struct rn_file *f;
	uint8_t *buf = vbuf;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->file == NULL && f->shadow_data == NULL) {
		return;
	}

	/*
	 * If we're using a fileio, we need to read the file in first.
	 * We then operate on it as if it were a shadow file, and simply
	 * write it back out at the end.
	 */
	uint8_t *filedata;
	size_t filesize, newsize;

	if (f->file != NULL) {
		struct fileio_attrs attrs;

		if (! fileio_getattr(f->file, &attrs)) {
			log_error("[%s] slot %u: fileio_getattr(): %s",
			    conn_name(conn), slot, strerror(errno));
			return;
		}

		/*
		 * If the offset is beyond current EOF, we extend the file.
		 * We can do this without reading the whole thing in by just
		 * redirecting to rn_api_fh_replace().
		 */
		if (offset >= attrs.size) {
			log_debug("[%s] slot %u: Redirecting to "
			    "rn_api_fh_replace().", conn_name(conn), slot);
			rn_api_fh_replace(conn, slot, vbuf, offset, length);
			return;
		}

		/* Allocate the new space as the "extra". */
		filedata = fileio_load_file(f->file, &attrs, length,
		    0, &filesize);
		if (filedata == NULL) {
			log_error("[%s] slot %u: fileio_load_file(): %s",
			    conn_name(conn), slot, strerror(errno));
			return;
		}
	} else {
		/* As above. */
		if (offset >= f->shadow_len) {
			log_debug("[%s] slot %u: Redirecting to "
			    "rn_api_fh_replace().", conn_name(conn), slot);
			rn_api_fh_replace(conn, slot, vbuf, offset, length);
			return;
		}

		filesize = f->shadow_len;
		filedata = realloc(f->shadow_data, filesize + length);
		if (filedata == NULL) {
			log_error("[%s] slot %u: unable to allocate %zu bytes "
			    "for insertion.", conn_name(conn), slot,
			    filesize + length);
			return;
		}
	}

	/*
	 * We now have filedata pointing to a buffer large enough
	 * to hold the result, containing the original data at
	 * the front.  Scoot the data after the insertion point to
	 * the end of the buffer, and copy the new data into its
	 * destination.
	 */
	newsize = filesize + length;
	uint8_t *from = filedata + offset;
	uint8_t *to = from + length;
	memmove(to, from, filesize - offset);
	memcpy(from, buf, length);

	if (f->file != NULL) {
		if (fileio_pwrite(f->file, filedata, newsize,
				  0) != (ssize_t)newsize) {
			log_error("[%s] %u: fileio_pwrite(): %s",
			    conn_name(conn), slot, strerror(errno));
		}
		free(filedata);
	} else {
		if (f->shadow_data != filedata) {
			free(f->shadow_data);
			f->shadow_data = filedata;
		}
		f->shadow_len = newsize;
	}
}

/*
 * rn_api_fh_delete_range --
 *	RetroNet API: Delete a range of bytes in a file.
 */
void
rn_api_fh_delete_range(struct nabu_connection *conn,
    uint8_t slot, uint32_t offset, uint16_t length)
{
	struct rn_file *f;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->shadow_data != NULL) {
		if (offset >= f->shadow_len || length == 0) {
			/* Nothing to delete. */
			return;
		}

		/* Clamp the length. */
		if (offset + length > f->shadow_len) {
			length -= (offset + length) - f->shadow_len;
		}

		/* We don't bother truncating the allocation. */
		size_t copysize = f->shadow_len - (offset + length);

		/* Scoot thge portion remaining into place. */
		if (copysize != 0) {
			memmove(&f->shadow_data[offset],
			    &f->shadow_data[offset + length],
			    copysize);
		}
		f->shadow_len -= length;
	} else if (f->file != NULL) {
		struct fileio_attrs attrs;

		if (! fileio_getattr(f->file, &attrs)) {
			log_error("[%s] slot %u: fileio_getattr(): %s",
			    conn_name(conn), slot, strerror(errno));
			return;
		}

		if (offset >= attrs.size || length == 0) {
			/* Nothing to delete. */
			return;
		}

		/* Clamp the length */
		if (offset + length > attrs.size) {
			length -= (offset + length) - attrs.size;
		}

		size_t copysize = attrs.size - (offset + length);

		/* Allocate a temporary buffer to hold the data. */
		uint8_t *buf = malloc(copysize);
		if (buf == NULL) {
			log_error("[%s] slot %u: unable to allocate %zu bytes "
			    "for temp buffer.", conn_name(conn), slot,
			    copysize);
			return;
		}

		ssize_t actual = fileio_pread(f->file, buf, copysize,
				 offset + length);
		if (actual != (ssize_t)copysize) {
			log_error("[%s] slot %u: "
			    "fileio_pread(%zu @ %u) -> %zd%s%s",
			    conn_name(conn), slot, copysize, offset + length,
			    actual,
			    actual == -1 ? " " : "",
			    actual == -1 ? strerror(errno) : "");
			free(buf);
			return;
		}

		/*
		 * Since we're writing in-place, we're past the point
		 * of not return.  Report errors, but don't abort on them.
		 */
		actual = fileio_pwrite(f->file, buf, copysize, offset);
		if (actual != (ssize_t)copysize) {
			log_error("[%s] slot %u: "
			    "fileio_pwrite(%zu @ %u) -> %zd%s%s",
			    conn_name(conn), slot, copysize, offset, actual,
			    actual == -1 ? " " : "",
			    actual == -1 ? strerror(errno) : "");
		}
		free(buf);
		if (! fileio_truncate(f->file, attrs.size - length)) {
			log_error("[%s] slot %u: fileio_truncate(%lld): %s",
			    conn_name(conn), slot,
			    (long long)attrs.size - length,
			    strerror(errno));
		}
	}
}

/*
 * rn_api_fh_truncate --
 *	RetroNet API: Truncate a file to 0 ("empty file")
 */
void
rn_api_fh_truncate(struct nabu_connection *conn, uint8_t slot)
{
	struct rn_file *f;

	f = rn_file_find(conn, slot);
	if (f == NULL) {
		log_debug("[%s] No file for slot %d.", conn_name(conn), slot);
		return;
	}

	if (f->shadow_data != NULL) {
		/* Don't bother re-allocating the backing store. */
		f->shadow_len = 0;
	} else if (f->file != NULL) {
		if (! fileio_truncate(f->file, 0)) {
			log_error("[%s] slot %u: fileio_truncate(0): %s",
			    conn_name(conn), slot, strerror(errno));
		}
	}
}
