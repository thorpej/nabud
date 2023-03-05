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
#include "missing.h"

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
	bool		(*io_getattr_location)(const char *, int, const char *,
			    struct fileio_attrs *);
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
			bool is_directory;
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

static int
fileio_local_resolve_path(const char *location, const char *local_root,
    int flags, char **fnamep)
{
	char *fname;

	if ((flags & FILEIO_O_LOCAL_ROOT) != 0 && local_root == NULL) {
		return EINVAL;
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
		return EINVAL;
	}

	if (local_root != NULL) {
		/* The local root must be an absolute path. */
		if (*local_root != '/') {
			return EINVAL;
		}
		if (check_local_root_escape(location)) {
			return EPERM;
		}
		/* local_root/location\0 */
		fname = malloc(strlen(local_root) + 1 +
		    strlen(location) + 1);
		if (fname != NULL) {
			sprintf(fname, "%s/%s", local_root, location);
		}
	} else {
		if (flags & FILEIO_O_LOCAL_ROOT) {
			return EPERM;
		}
		fname = strdup(location);
	}
	if (fname == NULL) {
		return ENOMEM;
	}

	*fnamep = fname;
	return 0;
}

static bool
fileio_local_io_open(struct fileio *f, const char *location,
    const char *local_root)
{
	int error;

	error = fileio_local_resolve_path(location, local_root, f->flags,
	    &f->location);
	if (error != 0) {
		errno = error;
		return false;
	}

	/* If open fails, caller will free f->location. */

	int open_flags = (f->flags & FILEIO_O_RDWR) ? O_RDWR : O_RDONLY;
	if (f->flags & FILEIO_O_CREAT) {
		open_flags |= O_CREAT;
	}
	if (f->flags & FILEIO_O_EXCL) {
		open_flags |= O_EXCL;
	}
	if (f->flags & FILEIO_O_TEXT) {
		open_flags |= O_TEXT;
	} else {
		open_flags |= O_BINARY;
	}

	f->local.fd = open(f->location, open_flags, 0666);
	if (f->local.fd < 0) {
		return false;
	}

	/*
	 * Only regular files, unless the caller says they're OK
	 * opening a directory (probably for a getattr call later).
	 */
	struct stat sb;
	if (fstat(f->local.fd, &sb) < 0) {
		goto bad;
	}
	if (S_ISDIR(sb.st_mode)) {
		if (f->flags & FILEIO_O_DIROK) {
			f->local.is_directory = true;
		} else {
			errno = EISDIR;
			goto bad;
		}
	} else if (!S_ISREG(sb.st_mode)) {
		errno = EPERM;
		goto bad;
	}

	return true;
 bad:
	close(f->local.fd);
	return false;
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

static void
fileio_stat_to_attrs(const char *path, const struct stat *sb,
    struct fileio_attrs *attrs)
{
	attrs->size = sb->st_size;
	attrs->mtime = sb->st_mtime;
#ifdef HAVE_STAT_ST_BIRTHTIME
	/* check for -1 in case some quirky file system returns it */
	attrs->btime = sb->st_birthtime != (time_t)-1 ? sb->st_birthtime : 0;
#else
	attrs->btime = 0;
#endif /* HAVE_STAT_ST_BIRTHTIME */
	attrs->is_directory = !!S_ISDIR(sb->st_mode);
	attrs->is_writable = access(path, R_OK | W_OK) == 0;
	attrs->is_seekable = true;
	attrs->is_local = true;
}

static bool
fileio_local_io_getattr(struct fileio *f, struct fileio_attrs *attrs)
{
	struct stat sb;

	if (fstat(f->local.fd, &sb) < 0) {
		return false;
	}

	fileio_stat_to_attrs(f->location, &sb, attrs);
	return true;
}

static bool
fileio_local_io_getattr_location(const char *location, int flags,
    const char *local_root, struct fileio_attrs *attrs)
{
	struct stat sb;
	char *path = NULL;
	bool rv = false;
	int error;

	error = fileio_local_resolve_path(location, local_root, flags,
	    &path);
	if (error == 0) {
		if (stat(path, &sb) == 0) {
			fileio_stat_to_attrs(path, &sb, attrs);
			rv = true;
		} else {
			error = errno;
		}
	}
	if (path != NULL) {
		free(path);
	}
	if (! rv) {
		errno = error;
	}
	return rv;
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
	if (f->local.is_directory) {
		/* XXX rewinddir()? */
		errno = EISDIR;
		return -1;
	}
	return lseek(f->local.fd, offset, whence);
}

static bool
fileio_local_io_truncate(struct fileio *f, off_t size)
{
	if (f->local.is_directory) {
		errno = EISDIR;
		return false;
	}
	return ftruncate(f->local.fd, size) == 0;
}

static ssize_t
fileio_local_io_read(struct fileio *f, void *buf, size_t len)
{
	if (f->local.is_directory) {
		errno = EISDIR;
		return -1;
	}
	return read(f->local.fd, buf, len);
}

static ssize_t
fileio_local_io_write(struct fileio *f, const void *buf, size_t len)
{
	if (f->local.is_directory) {
		errno = EISDIR;
		return -1;
	}
	return write(f->local.fd, buf, len);
}

static ssize_t
fileio_local_io_pread(struct fileio *f, void *buf, size_t len, off_t offset)
{
	if (f->local.is_directory) {
		errno = EISDIR;
		return -1;
	}
	return pread(f->local.fd, buf, len, offset);
}

static ssize_t
fileio_local_io_pwrite(struct fileio *f, const void *buf, size_t len,
    off_t offset)
{
	if (f->local.is_directory) {
		errno = EISDIR;
		return -1;
	}
	return pwrite(f->local.fd, buf, len, offset);
}

static const struct fileio_ops fileio_local_ops = {
	.io_open		=	fileio_local_io_open,
	.io_ok			=	fileio_local_io_ok,
	.io_getattr		=	fileio_local_io_getattr,
	.io_getattr_location	=	fileio_local_io_getattr_location,
	.io_close		=	fileio_local_io_close,
	.io_seek		=	fileio_local_io_seek,
	.io_truncate		=	fileio_local_io_truncate,
	.io_read		=	fileio_local_io_read,
	.io_write		=	fileio_local_io_write,
	.io_pread		=	fileio_local_io_pread,
	.io_pwrite		=	fileio_local_io_pwrite,
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
	attrs->is_local = false;

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
fileio_ops_for_location(const char *location, size_t loclen)
{
	const struct fileio_scheme_ops *fso;
	size_t schemelen;

	for (fso = fileio_scheme_ops; fso->scheme != NULL; fso++) {
		schemelen = strlen(fso->scheme);
		if (loclen < schemelen) {
			continue;
		}
		if (strncmp(location, fso->scheme, schemelen) == 0) {
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

	fso = fileio_ops_for_location(location, strlen(location));

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
 * fileio_resolve_path --
 *	Resolve a file location into a local path.  If the file's
 *	location is not local, NULL will be returned.  Caller is
 *	responsible for freeing the resulting path string.
 */
char *
fileio_resolve_path(const char *location, const char *local_root, int oflags)
{
	char *path;
	int error;

	if (! fileio_location_is_local(location, strlen(location))) {
		errno = EINVAL;
		return NULL;
	}

	error = fileio_local_resolve_path(location, local_root, oflags, &path);
	if (error != 0) {
		errno = error;
		return NULL;
	}
	return path;
}

/*
 * fileio_location_is_local --
 *	Returns true if the specified location is a local location.
 */
bool
fileio_location_is_local(const char *location, size_t loclen)
{
	const struct fileio_scheme_ops *fso;

	fso = fileio_ops_for_location(location, loclen);
	return fso->ops == &fileio_local_ops;
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
 * fileio_getattr_location --
 *	Do a fileio_getattr(), but on a location instead of a fileio.
 */
bool
fileio_getattr_location(const char *location, int flags,
    const char *local_root, struct fileio_attrs *attrs)
{
	const struct fileio_scheme_ops *fso;

	fso = fileio_ops_for_location(location, strlen(location));

	/* Sanitize the flags; only care about local root here. */
	flags &= FILEIO_O_LOCAL_ROOT;

	/*
	 * If the scheme supports a getattr-by-location directly, then do
	 * that.  Otherwise, we call back to opening the file to get the
	 * attrs and immediately closing it.
	 */
	if (fso->ops->io_getattr_location != NULL) {
		return (*fso->ops->io_getattr_location)(location, flags,
		    local_root, attrs);
	}

	struct fileio *f = fileio_open(location,
	    FILEIO_O_RDONLY | FILEIO_O_DIROK | flags, local_root, attrs);
	if (f == NULL) {
		return false;
	}
	fileio_close(f);

	return true;
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
		log_debug(LOG_SUBSYS_FILEIO, "Size of %s is %zu bytes.",
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
fileio_load_file_from_location(const char *location, int oflags, size_t extra,
    size_t maxsize, struct fileio_attrs *attrs, size_t *filesizep)
{
	struct fileio_attrs attrs_store;
	uint8_t *filebuf;
	struct fileio *f;

	if (attrs == NULL) {
		attrs = &attrs_store;
	}

	assert((oflags & ~FILEIO_O_TEXT) == 0);

	f = fileio_open(location, FILEIO_O_RDONLY | oflags, NULL, attrs);
	if (f == NULL) {
		log_error("Unable to open %s", location);
		return NULL;
	}

	filebuf = fileio_load_file(f, attrs, extra, maxsize, filesizep);

	fileio_close(f);

	return filebuf;
}
