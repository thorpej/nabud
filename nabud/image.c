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
 * Image management.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(HAVE_COMMONCRYPTO_H)
#define	COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonCrypto.h>
#elif defined(HAVE_OPENSSL)
#include <openssl/des.h>
#include <openssl/md5.h>
#endif

#include "libnabud/fileio.h"
#include "libnabud/log.h"

#include "conn.h"
#include "image.h"

static LIST_HEAD(, image_source) image_sources =
    LIST_HEAD_INITIALIZER(image_sources);
unsigned int image_source_count;

static TAILQ_HEAD(, image_channel) image_channels =
    TAILQ_HEAD_INITIALIZER(image_channels);
unsigned int image_channel_count;

static pthread_mutex_t image_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t image_cache_size;

/*
 * image_retain_locked --
 *	Retain (increment the refcnt) on the specified image.
 */
static void
image_retain_locked(struct nabu_image *img)
{
	img->refcnt++;
	assert(img->refcnt != 0);
}

/*
 * image_release_locked --
 *	Release the specified image.
 */
static struct nabu_image *
image_release_locked(struct nabu_image *img)
{
	if (img != NULL) {
		uint32_t ocnt = img->refcnt--;
		assert(ocnt > 0);
		if (ocnt > 1) {
			img = NULL;
		}
	}
	return img;
}

/*
 * image_free --
 *	Free an image.
 */
static void
image_free(struct nabu_image *img)
{
	if (img != NULL) {
		assert(img->refcnt == 0);
		free(img->name);
		free(img->data);
		free(img);
	}
}

/*
 * image_release --
 *	Relase an image.  This version is visible to outsiders.
 */
void
image_release(struct nabu_image *img)
{
	pthread_mutex_lock(&image_cache_lock);
	img = image_release_locked(img);
	pthread_mutex_unlock(&image_cache_lock);
	image_free(img);
}

/*
 * image_source_lookup --
 *	Look up an image source by name.
 */
static struct image_source *
image_source_lookup(const char *name)
{
	struct image_source *imgsrc;

	LIST_FOREACH(imgsrc, &image_sources, link) {
		if (strcmp(imgsrc->name, name) == 0) {
			return imgsrc;
		}
	}
	return NULL;
}

/*
 * image_add_source --
 *	Add an image source.
 */
void
image_add_source(char *name, char *root)
{
	if (image_source_lookup(name) != NULL) {
		log_error("Image source %s alreadty exists.", name);
		goto bad;
	}

	struct image_source *imgsrc = calloc(1, sizeof(*imgsrc));
	if (imgsrc != NULL) {
		imgsrc->name = name;
		imgsrc->root = root;
		LIST_INSERT_HEAD(&image_sources, imgsrc, link);
		image_source_count++;
		log_info("Adding Source %s at %s",
		    imgsrc->name, imgsrc->root);
	} else {
		log_error("Unable to allocate image source descriptor for %s",
		    name);
		goto bad;
	}
	return;
 bad:
	free(name);
	free(root);
}

/*
 * image_channel_lookup --
 *	Look up an image channel by number.
 */
struct image_channel *
image_channel_lookup(unsigned int number)
{
	struct image_channel *chan;

	TAILQ_FOREACH(chan, &image_channels, link) {
		if (chan->number == number) {
			return chan;
		}
	}
	return NULL;
}

/*
 * image_channel_enumerate --
 *	Enumerate all of the channels.
 */
bool
image_channel_enumerate(bool (*func)(struct image_channel *, void *), void *ctx)
{
	struct image_channel *chan;

	TAILQ_FOREACH(chan, &image_channels, link) {
		if (! (*func)(chan, ctx)) {
			return false;
		}
	}
	return true;
}

/*
 * image_add_channel --
 *	Add a channel.
 */
void
image_add_channel(image_channel_type type, char *name, char *source,
    const char *relpath, char *list_url, char *default_file,
    unsigned int number)
{
	struct image_channel *chan = NULL;
	size_t pathlen;
	char *pathstr = NULL;

	struct image_source *imgsrc = image_source_lookup(source);
	if (imgsrc == NULL) {
		log_error("Unknown image source: %s", source);
		goto bad;
	}

	if ((chan = image_channel_lookup(number)) != NULL) {
		log_error("Channel %u already exists (%s on %s).",
		    number, chan->name, chan->source->name);
		goto bad;
	}

	if (relpath != NULL) {
		/* Get rid of leading /'s */
		while (*relpath == '/') {
			relpath++;
		}
		if (*relpath == '\0') {
			relpath = NULL;
		}
	}
	if (relpath == NULL) {
		relpath = name;
	}
	pathlen = strlen(relpath) + strlen(imgsrc->root) + 2; /* / + NUL */
	chan = calloc(1, sizeof(*chan));
	pathstr = malloc(pathlen);
	if (chan == NULL || pathstr == NULL) {
		log_error("Unable to allocate descriptor for channel %u.",
		    number);
		goto bad;
	}
	snprintf(pathstr, pathlen, "%s/%s", imgsrc->root, relpath);

	chan->source = imgsrc;
	chan->type = type;
	chan->name = name;
	chan->path = pathstr;
	chan->list_url = list_url;
	chan->default_file = default_file;
	chan->number = number;
	TAILQ_INSERT_TAIL(&image_channels, chan, link);
	image_channel_count++;
	log_info("Adding %s channel %u (%s on %s) at %s",
	    chan->type == IMAGE_CHANNEL_PAK ? "pak" : "nabu",
	    chan->number, chan->name, chan->source->name, chan->path);
	if (chan->list_url != NULL) {
		log_info("Channel %u has a listing at: %s",
		    chan->number, chan->list_url);
	}
	if (chan->default_file != NULL) {
		log_info("Channel %u will default to '%s' for image 000001.",
		    chan->number, chan->default_file);
	}
	return;
 bad:
	if (chan != NULL) {
		free(chan);
	}
	if (pathstr != NULL) {
		free(pathstr);
	}
	free(name);
	free(source);
}

/*
 * image_cache_lookup_locked --
 *	Look up an image in the channel's image cache.  Gains a retain
 *	on the image, if found.
 */
static struct nabu_image *
image_cache_lookup_locked(struct image_channel *chan, uint32_t image)
{
	struct nabu_image *img;

	LIST_FOREACH(img, &chan->image_cache, link) {
		if (img->number == IMAGE_NUMBER_NAMED) {
			continue;
		}
		if (img->number == image) {
			image_retain_locked(img);
			return img;
		}
	}
	return NULL;
}

/*
 * image_cache_lookup_named_locked --
 *	Look up an image in the channel's image cache by name.
 *	This is used for named file selections.  Gains a retain
 *	on the image, if found.
 */
static struct nabu_image *
image_cache_lookup_named_locked(struct image_channel *chan,
    const char *name)
{
	struct nabu_image *img;

	LIST_FOREACH(img, &chan->image_cache, link) {
		if (img->number != IMAGE_NUMBER_NAMED) {
			continue;
		}
		if (strcmp(img->name, name) == 0) {
			image_retain_locked(img);
			return img;
		}
	}
	return NULL;
}

/*
 * image_cache_insert_locked --
 *	Insert an image into the image cache.  If the image
 *	already exists, we end up releasing the new one and
 *	using the one from the cache.
 *
 *	The image returned has 2 retains:
 *
 *	-> For new images, we start with a retain count of 1 (the
 *	   caller's retain) and the image cache also gains a retain.
 *
 *	-> For collisions, we start with a retain count of 1 (the
 *	   image cache's retain) and the gain another for the caller.
 */
static struct nabu_image *
image_cache_insert_locked(struct image_channel *chan, struct nabu_image *newimg)
{
	struct nabu_image *img;

	if (newimg->number == IMAGE_NUMBER_NAMED) {
		img = image_cache_lookup_named_locked(chan, newimg->name);
	} else {
		img = image_cache_lookup_locked(chan, newimg->number);
	}
	if (img == NULL) {
		image_retain_locked(newimg);
		LIST_INSERT_HEAD(&chan->image_cache, newimg, link);
		image_cache_size += newimg->length;

		log_info("Cached %s on Channel %u; "
		    "total cache size: %zu", newimg->name, chan->number,
		        image_cache_size);
		img = newimg;
	}
	return img;
}

/*
 * image_cache_clear --
 *	Clear the image cache for a channel.
 */
void
image_cache_clear(struct image_channel *chan)
{
	LIST_HEAD(, nabu_image) old_cache;
	struct nabu_image *img;
	void *listing;

	LIST_INIT(&old_cache);
	pthread_mutex_lock(&image_cache_lock);
	while ((img = LIST_FIRST(&chan->image_cache)) != NULL) {
		image_cache_size -= img->length;
		LIST_REMOVE(img, link);
		LIST_INSERT_HEAD(&old_cache, img, link);
	}
	listing = chan->listing;
	chan->listing = NULL;
	chan->listing_size = 0;
	pthread_mutex_unlock(&image_cache_lock);

	while ((img = LIST_FIRST(&old_cache)) != NULL) {
		LIST_REMOVE(img, link);
		image_release(img);
	}

	if (listing != NULL) {
		free(listing);
	}
}

/*
 * image_channel_fetch_listing --
 *	Return a copy of the channel's listing, fetching it
 *	from the server as necessary.
 */
char *
image_channel_copy_listing(struct image_channel *chan, size_t *sizep)
{
	char *data, *cp, *tmp;
	size_t allocsize, filesize;
	unsigned int attempt = 0;

 top:
	log_debug("[%s] Attempt #%d to get listing.", chan->name, attempt++);
	pthread_mutex_lock(&image_cache_lock);
	if (chan->listing == NULL) {
		/* No listing yet; need to fetch. */
		pthread_mutex_unlock(&image_cache_lock);
		log_debug("[%s] No cached listing; need to fetch.",
		    chan->name);
		goto fetch;
	}
	allocsize = chan->listing_size;
	pthread_mutex_unlock(&image_cache_lock);

	log_debug("[%s] Cached listing is %zu bytes.", chan->name, allocsize);
	data = malloc(allocsize);
	if (data == NULL) {
		log_error("[%s] Unable to allocate %zu byte for listing.",
		    chan->name, allocsize);
		return NULL;
	}

	pthread_mutex_lock(&image_cache_lock);
	if (chan->listing != NULL && allocsize >= chan->listing_size) {
		memcpy(data, chan->listing, chan->listing_size);
		*sizep = chan->listing_size;
		pthread_mutex_unlock(&image_cache_lock);
		log_debug("[%s] Copied %zu bytes of cached listing.",
		    chan->name, *sizep);
		return data;
	}
	/*
	 * If we got here, the size changed to be larger and and we need
	 * to try again.
	 */
	pthread_mutex_unlock(&image_cache_lock);
	free(data);
	goto top;

 fetch:
	if (chan->list_url == NULL) {
		/* No listing. */
		log_debug("[%s] No listing for this channel.", chan->name);
		return NULL;
	}

	/* Allocate an extra byte to ensure there's a \n\0 at the end. */
	log_debug("[%s] Fetching listing from %s", chan->name, chan->list_url);
	data = fileio_load_file_from_location(chan->list_url, 2, 0, &filesize);
	if (data == NULL) {
		log_error("[%s] Unable to fetch listing from %s\n",
		    chan->name, chan->list_url);
		return NULL;
	}
	allocsize = filesize + 2;
	data[filesize] = '\n';
	data[filesize + 1] = '\0';
	*sizep = allocsize;

	/* Now cache a copy. */
	cp = malloc(allocsize);
	if (cp == NULL) {
		log_error("[%s] Unable to allocate %zu bytes to cache listing.",
		    chan->name, allocsize);
		return data;
	}
	memcpy(cp, data, allocsize);

	pthread_mutex_lock(&image_cache_lock);
	tmp = chan->listing;
	chan->listing = cp;
	chan->listing_size = allocsize;
	pthread_mutex_unlock(&image_cache_lock);
	if (tmp != NULL) {
		free(tmp);
	}
	log_info("[%s] Cached %zu bytes of listing data.", chan->name,
	    allocsize);

	return data;
}

/*
 * image_nabu_name --
 *	Generate a NABU flat image name.
 */
static char *
image_nabu_name(uint32_t image)
{
	char namestr[sizeof("000001.nabu")];
	snprintf(namestr, sizeof(namestr), "%06X.nabu", image);
	return strdup(namestr);
}

#define	ENCRYPTED_PAK_NAME_SIZE	\
	sizeof("FE-A1-04-B7-3D-67-F8-8B-26-4C-0C-81-9B-F6-24-58.npak")

/*
 * image_encrypted_pak_name --
 *	Generate a NabuRetroNet encrypted PAK name from the given
 *	image number.
 */
static char *
image_encrypted_pak_name(uint32_t image)
{
#if defined(HAVE_COMMONCRYPTO_H) || defined(HAVE_OPENSSL)
	char namestr[sizeof("000001nabu")];
	char pakname[ENCRYPTED_PAK_NAME_SIZE];

	MD5_CTX ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];

	snprintf(namestr, sizeof(namestr), "%06Xnabu", image);
	MD5_Init(&ctx);
	MD5_Update(&ctx, namestr, sizeof(namestr) - 1);
	MD5_Final(digest, &ctx);

	snprintf(pakname, sizeof(pakname),
	    "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X.npak",
	    digest[0],  digest[1],  digest[2],  digest[3],
	    digest[4],  digest[5],  digest[6],  digest[7],
	    digest[8],  digest[9],  digest[10], digest[11],
	    digest[12], digest[13], digest[14], digest[15]);

	return strdup(pakname);
#else
	return NULL;
#endif
}

/*
 * image_pak_name --
 *	Generate a PAK image name.
 */
static char *
image_pak_name(uint32_t image, bool encrypted)
{
	char namestr[sizeof("000001.pak")];

	if (encrypted) {
		return image_encrypted_pak_name(image);
	}

	snprintf(namestr, sizeof(namestr), "%06X.pak", image);
	return strdup(namestr);
}

/*
 * image_from_nabu --
 *	Create an image descriptor from the provided NABU file buffer.
 */
static struct nabu_image *
image_from_nabu(struct image_channel *chan, uint32_t image,
    const char *image_name, uint8_t *filebuf, size_t filesize)
{
	char image_name_buf[sizeof("nabu-000001")];

	if (image_name == NULL) {
		snprintf(image_name_buf, sizeof(image_name_buf),
		    "nabu-%06X", image);
		image_name = image_name_buf;
	}

	struct nabu_image *img = calloc(1, sizeof(*img));
	if (img == NULL) {
		log_error("Unable to allocate image descriptor for %s.",
		    image_name);
		free(filebuf);
		return NULL;
	}

	img->channel = chan;
	img->name = strdup(image_name);
	img->data = filebuf;
	img->length = filesize;
	img->number = image;
	img->refcnt = 1;

	return img;
}

/*
 * image_decrypt_pak --
 *	Decrypt a PAK image.
 */
static bool
image_decrypt_pak(const uint8_t *src, uint8_t *dst, size_t len)
{
#if defined(HAVE_COMMONCRYPTO_H)
	uint8_t iv[] = NABU_PAK_IV;
	uint8_t key[] = NABU_PAK_KEY;
	CCCryptorStatus status;
	CCCryptorRef cryptor;
	size_t actual;

	status = CCCryptorCreate(kCCDecrypt, kCCAlgorithmDES, 0,
	    key, sizeof(key), iv, &cryptor);
	if (status == kCCSuccess) {
		status = CCCryptorUpdate(cryptor, src, len, dst, len, &actual);
		if (status == kCCSuccess) {
			status = CCCryptorFinal(cryptor, dst, len, &actual);
			if (status != kCCSuccess) {
				log_error("CCCryptorFinal() failed: %d",
				    status);
			}
		} else {
			log_error("CCCryptorUpdate() failed: %d", status);
		}
		CCCryptorRelease(cryptor);
	} else {
		log_error("CCCryptorCreate() failed: %d", status);
	}

	return status == kCCSuccess;
#elif defined(HAVE_OPENSSL)
	DES_cblock iv = NABU_PAK_IV;
	DES_cblock key = NABU_PAK_KEY;
	DES_key_schedule ks;

	DES_set_key_unchecked(&key, &ks);
	DES_ncbc_encrypt((const unsigned char *)src,
	    (unsigned char *)dst, (long)len, &ks, &iv, 0);

	return true;
#else
	return false;
#endif
}

/*
 * image_from_pak --
 *	Create an image descriptor from the provided PAK buffer.
 */
static struct nabu_image *
image_from_pak(struct image_channel *chan, uint32_t image,
    const char *image_name, uint8_t *pakbuf, size_t paklen,
    bool encrypted)
{
	char image_name_buf[sizeof("pak-000001")];
	uint8_t *pakdata;

	if (image_name == NULL) {
		snprintf(image_name_buf, sizeof(image_name_buf),
		    "pak-%06X", image);
		image_name = image_name_buf;
	}

	struct nabu_image *img = calloc(1, sizeof(*img));
	if (img == NULL) {
		log_error("Unable to allocate image descriptor for %s.",
		    image_name);
		goto bad;
	}

	if (encrypted) {
		if ((paklen % 8) != 0) {	/* XXX magic number */
			log_error("[%s] %s size %zu is not a multiple of "
			    "DES block size.", chan->name, image_name, paklen);
			goto bad;
		}

		pakdata = malloc(paklen);
		if (pakdata == NULL) {
			log_error("[%s] Unable to allocate buffer for "
			    "decrypted %s.", chan->name, image_name);
			goto bad;
		}

		log_debug("[%s] Decrypting PAK image %s.",
		    chan->name, image_name);
		    
		if (! image_decrypt_pak(pakbuf, pakdata, paklen)) {
			log_error("[%s] Unable to decrypt PAK image %s.",
			    chan->name, image_name);
			free(pakdata);
			goto bad;
		}
		free(pakbuf);
	} else {
		pakdata = pakbuf;
	}

	img->channel = chan;
	img->name = strdup(image_name);
	img->data = pakdata;
	img->length = paklen;
	img->number = image;
	img->refcnt = 1;

	return img;

 bad:
	free(pakbuf);
	return NULL;
}

/*
 * image_load_image_from_url --
 *	Load an image from the specified url.
 */
static struct nabu_image *
image_load_image_from_url(struct image_channel *chan, uint32_t image,
    const char *image_name, const char *url, bool encrypted)
{
	struct nabu_image *img;
	uint8_t *filebuf;
	size_t filesize;

	filebuf = fileio_load_file_from_location(url, 0, NABU_MAXSEGMENTSIZE,
	    &filesize);
	if (filebuf == NULL) {
		/* Error already logged. */
		return NULL;
	}

	if (chan->type == IMAGE_CHANNEL_PAK) {
		img = image_from_pak(chan, image, image_name, filebuf,
		    filesize, encrypted);
	} else {
		img = image_from_nabu(chan, image, image_name, filebuf,
		    filesize);
	}

	return img;
}

/*
 * image_channel_select --
 *	Select the channel for this connection from the index
 *	provided by the NABU.
 */
void
image_channel_select(struct nabu_connection *conn, int16_t channel)
{
	struct image_channel *chan;

	if (channel < 1 || channel > 0x100) {
		log_info("[%s] Invalid channel selection %d.",
		    conn_name(conn), channel);
		return;
	}

	chan = image_channel_lookup((unsigned int)channel);
	if (chan == NULL) {
		log_info("[%s] Channel %d not found.", conn_name(conn),
		    channel);
		return;
	}

	log_info("[%s] Selected channel %u (%s on %s).",
	    conn_name(conn), chan->number, chan->name, chan->source->name);

	conn_set_channel(conn, chan);
}

/*
 * image_load --
 *	Load the specified segment.
 */
struct nabu_image *
image_load(struct nabu_connection *conn, uint32_t image)
{
	char *image_url = NULL;
	struct nabu_image *img = NULL;
	struct image_channel *chan;
	char *selected_name = NULL;
	int rv;
	bool try_encrypted_pak = false;

	assert(image != IMAGE_NUMBER_NAMED);

	/*
	 * If the NABU is requesting image 000001, then we
	 * substitute a named file, if one is selected.
	 */
	if (image == 1) {
		selected_name = conn_get_selected_file(conn);
		if (selected_name != NULL) {
			image = IMAGE_NUMBER_NAMED;
		}
	}

	pthread_mutex_lock(&image_cache_lock);

	img = conn_get_last_image(conn);
	if (img != NULL) {
		/* Maybe a cache hit. */
		if (image == IMAGE_NUMBER_NAMED &&
		    strcmp(img->name, selected_name) == 0) {
			/* Cache hit! */
			log_debug("[%s] Connection cache hit for named "
			    "image: %s", conn_name(conn), img->name);
		} else if (image != IMAGE_NUMBER_NAMED &&
			   img->number == image) {
			/* Cache hit! */
			log_debug("[%s] Connection cache hit for "
			    "image %06X: %s", conn_name(conn), image,
			    img->name);
		} else {
			/* Boo, cache miss. */
			img = NULL;
		}
	}
	if (img != NULL) {
		image_retain_locked(img);
		pthread_mutex_unlock(&image_cache_lock);
		goto out;
	}

	chan = conn_get_channel(conn);
	if (chan == NULL) {
		log_error("[%s] No channel selected.", conn_name(conn));
		pthread_mutex_unlock(&image_cache_lock);
		goto out;
	}

	if ((img = image_cache_lookup_locked(chan, image)) != NULL) {
		struct nabu_image *oimg;

		/* Cache hit! */
		log_debug("Channel %u cache hit for image %06X: %s",
		    chan->number, image, img->name);

		/* Add an extra retain for the last-image cache. */
		image_retain_locked(img);
		oimg = conn_set_last_image(conn, img);
		oimg = image_release_locked(oimg);
		pthread_mutex_unlock(&image_cache_lock);
		image_free(oimg);
		goto out;
	}

	pthread_mutex_unlock(&image_cache_lock);

 try_again:
	if (selected_name != NULL) {
		rv = asprintf(&image_url, "%s/%s", chan->path, selected_name);
		assert(rv != -1 && image_url != NULL);
		log_debug("[%s] Loading '%s' from %s", conn_name(conn),
		    selected_name, image_url);
	} else {
		const char *imgtype;
		char *fname;

		if (chan->type == IMAGE_CHANNEL_PAK) {
			fname = image_pak_name(image, try_encrypted_pak);
			imgtype = "pak";
		} else {
			fname = image_nabu_name(image);
			imgtype = "nabu";
		}
		if (fname == NULL) {
			log_error("[%s] Unable to generate file name "
			    "for %s-%06X.", conn_name(conn),
			    imgtype, image);
		}
		rv = asprintf(&image_url, "%s/%s", chan->path, fname);
		assert(rv != -1 && image_url != NULL);
		log_debug("[%s] Loading %s-%06X from %s", conn_name(conn),
		    imgtype, image, image_url);
		free(fname);
	}

	img = image_load_image_from_url(chan, image, selected_name, image_url,
	    try_encrypted_pak);
	free(image_url);
	if (img != NULL) {
		struct nabu_image *oimg, *using_img;

		pthread_mutex_lock(&image_cache_lock);
		using_img = image_cache_insert_locked(chan, img);

		/* Add an extra retain for the last-image cache. */
		image_retain_locked(using_img);
		oimg = conn_set_last_image(conn, using_img);
		oimg = image_release_locked(oimg);
		if (using_img != img) {
			img = image_release_locked(img);
		} else {
			img = NULL;
		}
		pthread_mutex_unlock(&image_cache_lock);
		image_free(oimg);
		image_free(img);
		img = using_img;
	} else {
		if (selected_name == NULL &&
		    chan->type == IMAGE_CHANNEL_PAK && !try_encrypted_pak) {
			/*
			 * The unencrypted name didn't work.  While the
			 * original 1984 cycles are now being vended as
			 * unencrypted files for the most part, our config
			 * might be referencing an old Source, so we'll
			 * try the encrypted name if the regular name failed.
			 */
			try_encrypted_pak = true;
			goto try_again;
		}
	}

 out:
	if (selected_name != NULL) {
		free(selected_name);
	}
	return img;
}
