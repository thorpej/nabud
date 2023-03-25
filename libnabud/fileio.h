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

#ifndef fileio_h_included
#define	fileio_h_included

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct fileio;

struct fileio_attrs {
	off_t	size;
	time_t	mtime;		/* mod time */
	time_t	btime;		/* birth time */
	bool	is_directory;
	bool	is_writable;
	bool	is_seekable;
	bool	is_local;
};

struct fileio *	fileio_open(const char *, int, const char *,
			    struct fileio_attrs *);
void		fileio_close(struct fileio *);
off_t		fileio_seek(struct fileio *, off_t, int);
ssize_t		fileio_read(struct fileio *, void *, size_t);
ssize_t		fileio_write(struct fileio *, const void *, size_t);
ssize_t		fileio_pread(struct fileio *, void *, size_t, off_t);
ssize_t		fileio_pwrite(struct fileio *, const void *, size_t, off_t);
bool		fileio_getattr(struct fileio *, struct fileio_attrs *);
bool		fileio_getattr_location(const char *, int, const char *,
					struct fileio_attrs *);
bool		fileio_truncate(struct fileio *, off_t);
const char *	fileio_location(struct fileio *);

#define	FILEIO_O_ACCMODE	0x0007	/* access mode mask */
#define	FILEIO_O_RDONLY		0x0000
#define	FILEIO_O_RDWR		0x0001
#define	FILEIO_O_RDWP		0x0002	/* RDWR + lazy write-protect */
#define	FILEIO_O_LOCAL_ROOT	0x0008	/* require a local root */
#define	FILEIO_O_CREAT		0x0010
#define	FILEIO_O_EXCL		0x0020
#define	FILEIO_O_REGULAR	0x0040
#define	FILEIO_O_DIRECTORY	0x0080
#define	FILEIO_O_TEXT		0x0100	/* open as text; maybe CRLF xlation */

void	*fileio_load_file(struct fileio *, struct fileio_attrs *, size_t,
			  size_t, size_t *filesizep);

void	*fileio_load_file_from_location(const char *, int, size_t, size_t,
					struct fileio_attrs *, size_t *);

char	*fileio_resolve_path(const char *, const char *, int);
bool	fileio_location_is_local(const char *, size_t);

#endif /* fileio_h_included */
