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
 * File I/O abstraction.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fileio.h"
#include "log.h"

#include "libfetch/fetch.h"

#define	HTTP_PREFIX	SCHEME_HTTP "://"
#define	HTTPS_PREFIX	SCHEME_HTTPS "://"
#define	FTP_PREFIX	SCHEME_FTP "://"
#define	FILE_PREFIX	SCHEME_FILE "://"

struct fileio_ops {
	bool		(*io_open)(struct fileio *, const char *,
			    const char *);
	bool		(*io_ok)(struct fileio *, bool);
	bool		(*io_getattr)(struct fileio *, struct fileio_attrs *);
	void		(*io_close)(struct fileio *);

	off_t		(*io_seek)(struct fileio *, off_t, int);
	bool		(*io_truncate)(struct fileio *, off_t);

	ssize_t		(*io_read)(struct fileio *, void *, size_t);
	ssize_t		(*io_pread)(struct fileio *, void *, size_t, off_t);

	ssize_t		(*io_write)(struct fileio *, const void *, size_t);
	ssize_t		(*io_pwrite)(struct fileio *, const void *, size_t,
			    off_t);
};

struct fileio {
	char		*location;	/* might be a URL */
	int		flags;

	const struct fileio_ops *ops;

	union {
		struct {
			int fd;
		} local;
		struct {
			fetchIO *fio;
			struct url_stat ust;
		} remote;
	};
};

static bool
fileio_io_ok(struct fileio *f, bool writing)
{
	if (writing && (f->flags & FILEIO_O_RDWR) == 0) {
		errno = EBADF;
		return false;
	}
	return true;
}

/*
 * Local wrappers.
 */

typedef enum {
	Initial,
	Base,
	Have_Dot,
	Have_DotDot,
	Have_Slash,
	Have_SlashDot,
	Have_SlashDotDot,
} escape_check_state;

static bool
check_local_root_escape(const char *location)
{
	int depth = 0;
	escape_check_state state;

	/* Consume leading / characters. */
	while (*location == '/') {
		location++;
	}

	/* Set up the iniital state. */
	switch (*location) {
	case '.':	/* bare ".." is a bit of a special case. */
		location++;
		if (*location == '.') {
			state = Have_DotDot;
			location++;
			if (*location == '\0') {
				return true;
			}
		} else {
			state = Have_Dot;
		}
		break;

	default:
		state = Initial;
		break;
	}

	for (depth = 0; *location != '\0'; location++) {
		switch (state) {
		case Initial:
			switch (*location) {
			case '/':
				depth++;
				state = Have_Slash;
				break;
			}
			continue;

		case Base:
			switch (*location) {
			case '/':
				state = Have_Slash;
				break;
			}
			continue;

		case Have_Dot:
			switch (*location) {
			case '.':
				state = Have_DotDot;
				break;

			case '/':
				/* "./" does not increase depth */
				state = Have_Slash;
				break;

			default:
				state = Base;
				break;
			}
			continue;

		case Have_SlashDot:
			switch (*location) {
			case '.':
				state = Have_SlashDotDot;
				break;

			case '/':
				/* "./" does not increase depth */
				state = Have_Slash;
				break;

			default:
				state = Base;
				break;
			}
			continue;

		case Have_DotDot:
			switch (*location) {
			case '/':
				depth--;
				state = Have_Slash;
				if (depth < 0) {
					goto out;
				}
				break;

			default:
				state = Base;
				break;
			}
			continue;

		case Have_SlashDotDot:
			switch (*location) {
			case '/':
				depth--;
				state = Have_Slash;
				if (depth < 0) {
					goto out;
				}
				break;

			default:
				state = Base;
				break;
			}
			continue;

		case Have_Slash:
			switch (*location) {
			case '.':
				state = Have_SlashDot;
				break;

			case '/':
				break;

			default:
				depth++;
				state = Base;
				break;
			}
			continue;

		default:
			abort();
		}
	}

	/*
	 * Have_SlashDotDot ("some/path/.."), that decreases depth.
	 */
	if (state == Have_SlashDotDot) {
		depth--;
	}
 out:
	return depth < 0;
}

static bool
fileio_local_io_open(struct fileio *f, const char *location,
    const char *local_root)
{
	if ((f->flags & FILEIO_O_LOCAL_ROOT) != 0 && local_root == NULL) {
		errno = EINVAL;
		return false;
	}

	/*
	 * Strip file:// if it's there.  Note that we treat these as
	 * absolute paths and thus want to keep one leading /, so we
	 * strip off one less character.
	 */
	if (strncmp(location, FILE_PREFIX, strlen(FILE_PREFIX)) == 0) {
		location += strlen(FILE_PREFIX) - 1;
	}

	/*
	 * If we have an absolute path, strip off any extra / characters.
	 */
	if (location[0] == '/') {
		while (location[1] == '/') {
			location++;
		}
	}

	if (strlen(location) == 0) {
		errno = EINVAL;
		return false;
	}

	if (local_root != NULL) {
		/* The local root must be an absolute path. */
		if (*local_root != '/') {
			errno = EINVAL;
			return false;
		}
		if (check_local_root_escape(location)) {
			errno = EPERM;
			return false;
		}
		/* local_root/location\0 */
		f->location = malloc(strlen(local_root) + 1 +
		    strlen(location) + 1);
		if (f->location != NULL) {
			sprintf(f->location, "%s/%s", local_root, location);
		}
	} else {
		if (f->flags & FILEIO_O_LOCAL_ROOT) {
			errno = EPERM;
			return false;
		}
		f->location = strdup(location);
	}
	if (f->location == NULL) {
		errno = ENOMEM;
		return false;
	}
	/* If open fails, caller will free f->location. */

	int open_flags = (f->flags & FILEIO_O_RDWR) ? O_RDWR : O_RDONLY;
	if (f->flags & FILEIO_O_CREAT) {
		open_flags |= O_CREAT;
	}

	f->local.fd = open(f->location, open_flags);
	if (f->local.fd < 0) {
		return false;
	}

	/* Allow only regular files. */
	struct stat sb;
	if (fstat(f->local.fd, &sb) < 0 || !S_ISREG(sb.st_mode)) {
		close(f->local.fd);
		return false;
	}

	return true;
}

static bool
fileio_local_io_ok(struct fileio *f, bool writing)
{
	if (f->local.fd < 0) {
		errno = EBADF;
		return false;
	}
	return fileio_io_ok(f, writing);
}

static bool
fileio_local_io_getattr(struct fileio *f, struct fileio_attrs *attrs)
{
	struct stat sb;

	if (fstat(f->local.fd, &sb) < 0) {
		return false;
	}
	attrs->size = sb.st_size;
	attrs->mtime = sb.st_mtime;
	attrs->btime = 0;		/* XXX HAVE_STAT_ST_BIRTHTIME */
	attrs->is_directory = !!S_ISDIR(sb.st_mode);
	attrs->is_writable = access(f->location, R_OK | W_OK) == 0;
	attrs->is_seekable = true;

	return true;
}

static void
fileio_local_io_close(struct fileio *f)
{
	if (f->local.fd >= 0) {
		close(f->local.fd);
	}
}

static off_t
fileio_local_io_seek(struct fileio *f, off_t offset, int whence)
{
	return lseek(f->local.fd, offset, whence);
}

static bool
fileio_local_io_truncate(struct fileio *f, off_t size)
{
	return ftruncate(f->local.fd, size) == 0;
}

static ssize_t
fileio_local_io_read(struct fileio *f, void *buf, size_t len)
{
	return read(f->local.fd, buf, len);
}

static ssize_t
fileio_local_io_write(struct fileio *f, const void *buf, size_t len)
{
	return write(f->local.fd, buf, len);
}

static ssize_t
fileio_local_io_pread(struct fileio *f, void *buf, size_t len, off_t offset)
{
	return pread(f->local.fd, buf, len, offset);
}

static ssize_t
fileio_local_io_pwrite(struct fileio *f, const void *buf, size_t len,
    off_t offset)
{
	return pwrite(f->local.fd, buf, len, offset);
}

static const struct fileio_ops fileio_local_ops = {
	.io_open	=	fileio_local_io_open,
	.io_ok		=	fileio_local_io_ok,
	.io_getattr	=	fileio_local_io_getattr,
	.io_close	=	fileio_local_io_close,
	.io_seek	=	fileio_local_io_seek,
	.io_truncate	=	fileio_local_io_truncate,
	.io_read	=	fileio_local_io_read,
	.io_write	=	fileio_local_io_write,
	.io_pread	=	fileio_local_io_pread,
	.io_pwrite	=	fileio_local_io_pwrite,
};

/*
 * Remote wrappers.
 */
static bool
fileio_remote_io_open(struct fileio *f, const char *location,
    const char *local_root)
{
	f->location = strdup(location);
	if (f->location == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	/* If open fails, caller will free f->location. */

	f->remote.fio = fetchXGetURL(f->location, &f->remote.ust, "");
	if (f->remote.fio == NULL) {
		return false;
	}

	if (f->remote.ust.size < 0) {	/* XXX */
		fetchIO_close(f->remote.fio);
		return false;
	}

	return true;
}

static bool
fileio_remote_io_ok(struct fileio *f, bool writing)
{
	if (f->remote.fio == NULL) {
		errno = EBADF;
		return false;
	}
	return fileio_io_ok(f, writing);
}

static bool
fileio_remote_io_getattr(struct fileio *f, struct fileio_attrs *attrs)
{
	attrs->size = f->remote.ust.size;
	attrs->mtime = f->remote.ust.mtime;
	attrs->btime = 0;
	attrs->is_directory = false;
	attrs->is_writable = false;
	attrs->is_seekable = false;

	return true;
}

static void
fileio_remote_io_close(struct fileio *f)
{
	if (f->remote.fio != NULL) {
		fetchIO_close(f->remote.fio);
	}
}

static ssize_t
fileio_remote_io_read(struct fileio *fileio, void *buf, size_t len)
{
	return fetchIO_read(fileio->remote.fio, buf, len);
}

static const struct fileio_ops fileio_remote_ops = {
	.io_open	=	fileio_remote_io_open,
	.io_ok		=	fileio_remote_io_ok,
	.io_getattr	=	fileio_remote_io_getattr,
	.io_close	=	fileio_remote_io_close,
	.io_read	=	fileio_remote_io_read,
};

const struct fileio_scheme_ops {
	const char *scheme;
	const struct fileio_ops *ops;
} fileio_scheme_ops[] = {
	{ .scheme = HTTP_PREFIX,	.ops = &fileio_remote_ops },
	{ .scheme = HTTPS_PREFIX,	.ops = &fileio_remote_ops },
	{ .scheme = FTP_PREFIX,		.ops = &fileio_remote_ops },
	{ .scheme = FILE_PREFIX,	.ops = &fileio_local_ops },
	{ .scheme = NULL,		.ops = &fileio_local_ops },
};

static void
fileio_free(struct fileio *f)
{
	if (f->location != NULL) {
		free(f->location);
	}
	free(f);
}

static const struct fileio_scheme_ops *
fileio_ops_for_location(const char *location)
{
	const struct fileio_scheme_ops *fso;

	for (fso = fileio_scheme_ops; fso->scheme != NULL; fso++) {
		if (strncmp(location, fso->scheme, strlen(fso->scheme)) == 0) {
			break;
		}
	}
	return fso;
}

/*
 * fileio_open --
 *	Open a file.
 */
struct fileio *
fileio_open(const char *location, int flags, const char *local_root,
    struct fileio_attrs *attrs)
{
	const struct fileio_scheme_ops *fso;
	struct fileio *f;

	fso = fileio_ops_for_location(location);

	if (fso->ops->io_write == NULL && (flags & FILEIO_O_RDWR) != 0) {
		errno = ENOTSUP;
		return NULL;
	}

	f = calloc(1, sizeof(*f));
	if (f == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	f->ops = fso->ops;
	f->flags = flags;

	/* back-end sets up f->location */
	if ((*f->ops->io_open)(f, location, local_root)) {
		if (attrs == NULL ||
		    (*f->ops->io_getattr)(f, attrs)) {
			return f;
		}
		(*f->ops->io_close)(f);
	}

	fileio_free(f);
	return NULL;
}

/*
 * fileio_close --
 *	Close a file.
 */
void
fileio_close(struct fileio *f)
{
	(*f->ops->io_close)(f);
	fileio_free(f);
}

/*
 * fileio_location --
 *	Return the location of the file.  Note, this string is
 *	only valid for the lifetime of the fileio object.
 */
const char *
fileio_location(struct fileio *f)
{
	return f->location;
}

/*
 * fileio_getattr --
 *	Get attributes of a file.
 */
bool
fileio_getattr(struct fileio *f, struct fileio_attrs *attrs)
{
	bool rv = false;

	if ((*f->ops->io_ok)(f, false)) {
		/* Everybody has to support this one. */
		rv = (*f->ops->io_getattr)(f, attrs);
	}
	return rv;
}

/*
 * fileio_truncate --
 *	Truncate a file.
 */
bool
fileio_truncate(struct fileio *f, off_t size)
{
	if (size < 0) {
		return false;
	}
	if (f->ops->io_truncate == NULL) {
		errno = ENOTSUP;
		return false;
	} else if (! (*f->ops->io_ok)(f, true)) {
		return false;
	}
	return (*f->ops->io_truncate)(f, size);
}

/*
 * fileio_seek --
 *	Seek to a position in a file.
 */
off_t
fileio_seek(struct fileio *f, off_t offset, int whence)
{
	off_t pos = -1;

	if (f->ops->io_seek == NULL) {
		errno = ENOTSUP;
	} else if ((*f->ops->io_ok)(f, false)) {
		pos = (*f->ops->io_seek)(f, offset, whence);
	}
	return pos;
}

/*
 * fileio_read --
 *	Read from a file.
 */
ssize_t
fileio_read(struct fileio *f, void *buf, size_t len)
{
	ssize_t actual = -1;

	if ((*f->ops->io_ok)(f, false)) {
		/* Everybody has to support this one. */
		actual = (*f->ops->io_read)(f, buf, len);
	}
	return actual;
}

/*
 * fileio_pread --
 *	Positional read from a file.
 */
ssize_t
fileio_pread(struct fileio *f, void *buf, size_t len, off_t offset)
{
	ssize_t actual = -1;

	if (f->ops->io_pread == NULL) {
		errno = ENOTSUP;
	} else if ((*f->ops->io_ok)(f, false)) {
		actual = (*f->ops->io_pread)(f, buf, len, offset);
	}
	return actual;
}

/*
 * fileio_write --
 *	Write to a file.
 */
ssize_t
fileio_write(struct fileio *f, const void *buf, size_t len)
{
	ssize_t actual = -1;

	if (f->ops->io_write == NULL) {
		errno = ENOTSUP;
	} else if ((*f->ops->io_ok)(f, true)) {
		actual = (*f->ops->io_write)(f, buf, len);
	}
	return actual;
}

/*
 * fileio_pwrite --
 *	Positional write to a file.
 */
ssize_t
fileio_pwrite(struct fileio *f, const void *buf, size_t len, off_t offset)
{
	ssize_t actual = -1;

	if (f->ops->io_pwrite == NULL) {
		errno = ENOTSUP;
	} else if ((*f->ops->io_ok)(f, true)) {
		actual = (*f->ops->io_pwrite)(f, buf, len, offset);
	}
	return actual;
}

/*
 * fileio_load_file --
 *	Load a file from the specified fileio.
 */
void *
fileio_load_file(struct fileio *f, struct fileio_attrs *attrs, size_t extra,
    size_t maxsize, size_t *filesizep)
{
	struct fileio_attrs attrs_store;
	size_t filesize;
	uint8_t *filebuf;

	if (attrs == NULL) {
		attrs = &attrs_store;
		if (! fileio_getattr(f, attrs)) {
			log_error("Unable to get attributes of %s",
			    fileio_location(f));
			return NULL;
		}
	}

	if (attrs->size < 0) {
		/* XXX Support for chunked transfer encodings. */
		log_error("Size for %s is unavailable.",
		    fileio_location(f));
		return NULL;
	} else if (attrs->size == 0 ||
		   (maxsize != 0 && attrs->size > maxsize)) {
		log_error("Size of %s (%lld) is nonsensical.",
		    fileio_location(f), (long long)attrs->size);
		return NULL;
	} else {
		filesize = (size_t)attrs->size;
		log_debug("Size of %s is %zu bytes.",
		    fileio_location(f), filesize);
	}

	if ((filebuf = malloc(filesize + extra)) == NULL) {
		log_error("Unable to allocate %zu bytes for %s",
		    filesize + extra, fileio_location(f));
		return NULL;
	}
	if (fileio_read(f, filebuf, filesize) != (ssize_t)filesize) {
		log_error("Unable to read %s", fileio_location(f));
		free(filebuf);
		return NULL;
	}

	*filesizep = filesize;
	return filebuf;
}

/*
 * fileio_load_file_from_location --
 *	Load a file from the specified location.
 */
void *
fileio_load_file_from_location(const char *location, size_t extra,
    size_t maxsize, size_t *filesizep)
{
	struct fileio_attrs attrs;
	uint8_t *filebuf;
	struct fileio *f;

	f = fileio_open(location, FILEIO_O_RDONLY, NULL, &attrs);
	if (f == NULL) {
		log_error("Unable to open %s", location);
		return NULL;
	}

	filebuf = fileio_load_file(f, &attrs, extra, maxsize, filesizep);

	fileio_close(f);

	return filebuf;
}
