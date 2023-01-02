/*-
 * Copyright (c) 2022 Jason R. Thorpe.
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

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fileio.h"
#include "log.h"

#include "../libfetch/fetch.h"

/*
 * fileio_load_from_url --
 *	Load an file from the specified url.
 */
void *
fileio_load_from_url(const char *url, size_t maxsize, size_t *filesizep)
{
	struct url_stat ust;
	uint8_t *filebuf;
	size_t filesize;
	fetchIO *fio;

	fio = fetchXGetURL(url, &ust, "");
	if (fio == NULL) {
		log_error("Unable to fetch %s", url);
		return NULL;
	}

	if (ust.size < 0) {
		/* XXX Support for chunked transfer encodings. */
		log_error("Size for %s unavailable.", url);
		fetchIO_close(fio);
		return NULL;
	} else if (ust.size == 0 || (maxsize != 0 && ust.size > maxsize)) {
		log_error("Size of %s (%lld) is nonsensical.",
		    url, (long long)ust.size);
		fetchIO_close(fio);
		return NULL;
	} else {
		filesize = (size_t)ust.size;
		log_debug("Size of %s is %zu bytes.", url, filesize);
	}
	if ((filebuf = malloc(filesize)) == NULL) {
		log_error("Unable to allocate %zu bytes for %s",
		    filesize, url);
		fetchIO_close(fio);
		return NULL;
	}
	if (fetchIO_read(fio, filebuf, filesize) != (ssize_t)filesize) {
		log_error("Unable to read %s", url);
		fetchIO_close(fio);
		free(filebuf);
		return NULL;
	}

	*filesizep = filesize;
	return filebuf;
}
