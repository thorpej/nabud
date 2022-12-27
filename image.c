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
 * Segment management.
 */

#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conn.h"
#include "image.h"
#include "log.h"

static const char *images_directory;

/*
 * image_init --
 *	Initialize the segment repository.
 */
bool
image_init(const char *images_dir)
{
	struct stat sb;

	if (stat(images_dir, &sb) < 0) {
		log_error("stat() on images directory %s failed: %s",
		    images_dir, strerror(errno));
		return false;
	}
	if (!S_ISDIR(sb.st_mode)) {
		log_error("Images directory %s is not a directory.",
		    images_dir);
		return false;
	}

	images_directory = images_dir;

	return true;
}

/*
 * image_load --
 *	Load the specified segment.
 */
struct nabu_image *
image_load(struct nabu_connection *conn, uint32_t image)
{
	struct nabu_image *img;

	if ((img = conn->last_image) != NULL && img->number == image) {
		/* Cache hit! */
		log_debug("[%s] Cache hit for image 0x%08x", conn->name,
		    image);
		return img;
	}

	return NULL;	/* XXX */
}

/*
 * image_release --
 *	Release the specified segment.
 */
void
image_release(struct nabu_image *img)
{
	/* XXX */
}
