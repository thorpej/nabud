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

#include <sys/stat.h>
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
#else
#define NO_PAK_FILE_SUPPORT
#endif

#include "conn.h"
#include "image.h"
#include "log.h"

#include "../libfetch/fetch.h"

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
 *	image_cache_lock must be held.
 */
static void
image_retain_locked(struct nabu_image *img)
{
	img->refcnt++;
	assert(img->refcnt != 0);
}

/*
 * image_release --
 *	Release the specified image.
 *	image_cache_lock must NOT be held.
 */
static void
image_release(struct nabu_image *img)
{
	uint32_t ocnt;

	pthread_mutex_lock(&image_cache_lock);
	ocnt = img->refcnt--;
	pthread_mutex_unlock(&image_cache_lock);

	assert(ocnt > 0);
	if (ocnt == 1) {
		free(img->name);
		free(img->data);
		free(img);
	}
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
static struct image_channel *
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
 * image_add_channel --
 *	Add a channel.
 */
void
image_add_channel(image_channel_type type, char *name, char *source,
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

#ifdef NO_PAK_FILE_SUPPORT
	if (type == IMAGE_CHANNEL_PAK) {
		log_error("Skipping pak channel %u (%s on %s); "
		    "no pak file support.");
		goto bad;
	}
#endif /* NO_PAK_FILE_SUPPORT */

	pathlen = strlen(name) + strlen(imgsrc->root) + 2; /* / + NUL */
	chan = calloc(1, sizeof(*chan));
	pathstr = malloc(pathlen);
	if (chan == NULL || pathstr == NULL) {
		log_error("Unable to allocate descriptor for channel %u.",
		    number);
		goto bad;
	}
	snprintf(pathstr, pathlen, "%s/%s", imgsrc->root, name);

	chan->source = imgsrc;
	chan->type = type;
	chan->name = name;
	chan->path = pathstr;
	chan->number = number;
	TAILQ_INSERT_TAIL(&image_channels, chan, link);
	image_channel_count++;
	log_info("Adding %s channel %u (%s on %s) at %s",
	    chan->type == IMAGE_CHANNEL_PAK ? "pak" : "nabu",
	    chan->number, chan->name, chan->source->name, chan->path);
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
 *	Look up an image in the channel's image cache.  This is
 *	used by image_cache_lookup() and image_cache_insert().
 */
static struct nabu_image *
image_cache_lookup_locked(struct image_channel *chan, uint32_t image)
{
	struct nabu_image *img;

	LIST_FOREACH(img, &chan->image_cache, link) {
		if (img->number == image) {
			image_retain_locked(img);
			return img;
		}
	}
	return NULL;
}

/*
 * image_cache_lookup --
 *	Look up an image in the channel's image cache.
 */
static struct nabu_image *
image_cache_lookup(struct image_channel *chan, uint32_t image)
{
	struct nabu_image *img;

	pthread_mutex_lock(&image_cache_lock);
	img = image_cache_lookup_locked(chan, image);
	pthread_mutex_unlock(&image_cache_lock);

	return img;
}

/*
 * image_cache_insert --
 *	Insert an image into the image cache.  If the image
 *	already exists, we release the new one and return
 *	the one from the cache.
 */
static struct nabu_image *
image_cache_insert(struct image_channel *chan, struct nabu_image *newimg)
{
	struct nabu_image *img;
	size_t size;

	pthread_mutex_lock(&image_cache_lock);
	img = image_cache_lookup_locked(chan, newimg->number);
	if (img == NULL) {
		image_retain_locked(newimg);
		LIST_INSERT_HEAD(&chan->image_cache, newimg, link);
		image_cache_size += newimg->length;
	}
	size = image_cache_size;
	pthread_mutex_unlock(&image_cache_lock);

	if (img == NULL) {
		log_info("Cached %s on Channel %u; "
		    "total cache size: %zu", newimg->name, chan->number, size);
		return newimg;
	}

	image_release(newimg);
	return img;
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

#define	PAK_NAME_SIZE	\
	sizeof("FE-A1-04-B7-3D-67-F8-8B-26-4C-0C-81-9B-F6-24-58.npak")

#ifndef NO_PAK_FILE_SUPPORT
/*
 * image_pak_name --
 *	Generate a NabuRetroNet PAK name from the given image number.
 */
static char *
image_pak_name(uint32_t image)
{
	char namestr[sizeof("000001nabu")];
	char pakname[PAK_NAME_SIZE];

#if defined(HAVE_COMMONCRYPTO_H) || defined(HAVE_OPENSSL)
	MD5_CTX ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];

	snprintf(namestr, sizeof(namestr), "%06Xnabu", image);
	MD5_Init(&ctx);
	MD5_Update(&ctx, namestr, sizeof(namestr) - 1);
	MD5_Final(digest, &ctx);
#else
#error Unable to generate PAK file names!
#endif

	snprintf(pakname, sizeof(pakname),
	    "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X.npak",
	    digest[0],  digest[1],  digest[2],  digest[3],
	    digest[4],  digest[5],  digest[6],  digest[7],
	    digest[8],  digest[9],  digest[10], digest[11],
	    digest[12], digest[13], digest[14], digest[15]);

	return strdup(pakname);
}
#endif /* ! NO_PAK_FILE_SUPPORT */

/*
 * image_from_nabu --
 *	Create an image descriptor from the provided NABU file buffer.
 */
static struct nabu_image *
image_from_nabu(struct image_channel *chan, uint32_t image, uint8_t *filebuf,
    size_t filesize)
{
	char image_name[sizeof("nabu-000001")];

	snprintf(image_name, sizeof(image_name), "nabu-%06X", image);

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

#ifndef NO_PAK_FILE_SUPPORT
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
#error Unable to decrypt PAK files!
#endif
}

/*
 * image_from_pak --
 *	Create an image descriptor from the provided PAK buffer.
 */
static struct nabu_image *
image_from_pak(struct image_channel *chan, uint32_t image,
    const uint8_t *pakbuf, size_t paklen)
{
	char image_name[sizeof("pak-000001")];

	snprintf(image_name, sizeof(image_name), "pak-%06X", image);

	if ((paklen % 8) != 0) {	/* XXX magic number */
		log_error("%s size %zu is not a multiple of DES block size.",
		    image_name, paklen);
		return NULL;
	}

	uint8_t *pakdata = malloc(paklen);
	if (pakdata == NULL) {
		log_error("Unable to allocate buffer for decrypted %s.",
		    image_name);
		return NULL;
	}

	struct nabu_image *img = calloc(1, sizeof(*img));
	if (img == NULL) {
		log_error("Unable to allocate image descriptor for %s.",
		    image_name);
		free(pakdata);
		return NULL;
	}

	if (! image_decrypt_pak(pakbuf, pakdata, paklen)) {
		log_error("Unable to decrypt PAK image %s.", image_name);
		free(pakdata);
		return NULL;
	}

	img->channel = chan;
	img->name = strdup(image_name);
	img->data = pakdata;
	img->length = paklen;
	img->number = image;
	img->refcnt = 1;

	return img;
}
#endif /* ! NO_PAK_FILE_SUPPORT */

/*
 * image_load_image_from_url --
 *	Load an image from the specified url.
 */
static struct nabu_image *
image_load_image_from_url(struct image_channel *chan, uint32_t image,
    const char *url)
{
	struct url_stat ust;
	uint8_t *filebuf;
	size_t filesize;
	struct nabu_image *img;
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
	} else if (ust.size == 0 || ust.size > NABU_MAXSEGMENTSIZE) {
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

#ifndef NO_PAK_FILE_SUPPORT
	if (chan->type == IMAGE_CHANNEL_PAK) {
		img = image_from_pak(chan, image, filebuf, filesize);
		free(filebuf);
	} else
#endif /* ! NO_PAK_FILE_SUPPORT */
	{
		img = image_from_nabu(chan, image, filebuf, filesize);
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
		    conn->name, channel);
		return;
	}

	chan = image_channel_lookup((unsigned int)channel);
	if (chan == NULL) {
		log_info("[%s] Channel %d not found.", conn->name, channel);
		return;
	}

	log_info("[%s] Selected channel %u (%s on %s).",
	    conn->name, chan->number, chan->name, chan->source->name);
	conn->channel = chan;
}

/*
 * image_use --
 *	Indicate that the connection is now using an image.  Assumes
 *	the image has already been properly retained.
 */
static void
image_use(struct nabu_connection *conn, struct nabu_image *img)
{
	image_done(conn, conn->last_image);
	conn->last_image = img;
	log_info("[%s] Using image %s from Channel %u.",
	    conn->name, img->name, img->channel->number);
}

/*
 * image_done --
 *	Indicate that the connection is done with it's
 *	cached image.
 */
void
image_done(struct nabu_connection *conn, struct nabu_image *img)
{
	if (conn->last_image != NULL && conn->last_image == img) {
		log_info("[%s] Done with image %s.", conn->name,
		    img->name);
		conn->last_image = NULL;
		image_release(img);
	}
}

/*
 * image_load --
 *	Load the specified segment.
 */
struct nabu_image *
image_load(struct nabu_connection *conn, uint32_t image)
{
	char *fname, *image_url = NULL;
	const char *imgtype;
	struct nabu_image *img;

	if ((img = conn->last_image) != NULL && img->number == image) {
		/* Cache hit! */
		log_debug("[%s] Connection cache hit for image %06X: %s",
		    conn->name, image, img->name);
		return img;
	}

	if (conn->channel == NULL) {
		log_error("[%s] No channel selected.", conn->name);
		return NULL;
	}

	if ((img = image_cache_lookup(conn->channel, image)) != NULL) {
		/* Cache hit! */
		log_debug("Channel %u cache hit for image %06X: %s",
		    conn->channel->number, image, img->name);
		image_use(conn, img);
		return img;
	}

#ifndef NO_PAK_FILE_SUPPORT
	if (conn->channel->type == IMAGE_CHANNEL_PAK) {
		fname = image_pak_name(image);
		imgtype = "pak";
	} else
#endif /* ! NO_PAK_FILE_SUPPORT */
	{
		fname = image_nabu_name(image);
		imgtype = "nabu";
	}

	asprintf(&image_url, "%s/%s", conn->channel->path, fname);
	assert(image_url != NULL);
	log_debug("[%s] Loading %s-%06X from %s", conn->name, imgtype, image,
	    image_url);
	free(fname);

	img = image_load_image_from_url(conn->channel, image, image_url);
	free(image_url);
	if (img != NULL) {
		img = image_cache_insert(conn->channel, img);
		image_use(conn, img);
		return img;
	}

	return NULL;
}
