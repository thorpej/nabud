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

#ifndef image_h_included
#define	image_h_included

#include <stdbool.h>
#include <stdint.h>

#include "libnabud/nbsd_queue.h"

struct image_source {
	LIST_ENTRY(image_source) link;
	char		*name;
	char		*root;
};

typedef enum {
	IMAGE_CHANNEL_INVALID	=	0,
	IMAGE_CHANNEL_PAK	=	1,
	IMAGE_CHANNEL_NABU	=	2,
} image_channel_type;

#define	IMAGE_NUMBER_NAMED	((uint32_t)-1)

struct image_channel {
	TAILQ_ENTRY(image_channel) link;
	struct image_source *source;
	image_channel_type type;
	char		*name;
	char		*path;
	char		*list_url;
	char		*default_file;
	void		*listing;
	size_t		listing_size;
	unsigned int	number;
	LIST_HEAD(, nabu_image) image_cache;
};

struct nabu_image {
	struct image_channel *channel;
	LIST_ENTRY(nabu_image) link;
	char		*name;
	uint8_t		*data;
	size_t		length;
	uint32_t	number;
	uint32_t	refcnt;
};

struct nabu_connection;

void	image_add_source(char *, char *);
void	image_add_channel(image_channel_type, char *, char *, const char *,
	    char *, char *, unsigned int);

struct image_channel *image_channel_lookup(unsigned int);
bool	image_channel_enumerate(bool (*)(struct image_channel *, void *),
				void *);
void	image_cache_clear(struct image_channel *);
char *	image_channel_copy_listing(struct image_channel *, size_t *);

void	image_channel_select(struct nabu_connection *, int16_t);
struct nabu_image *image_load(struct nabu_connection *, uint32_t);
void	image_release(struct nabu_image *, bool);

#endif /* image_h_included */
