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

#ifdef __APPLE__	/* Use CommonCrypto on macOS */
#define	COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonCrypto.h>
#else
#include <openssl/des.h>
#include <openssl/md5.h>
#endif /* __APPLE__ */

#include "conn.h"
#include "image.h"
#include "log.h"

static LIST_HEAD(, image_source) image_sources =
    LIST_HEAD_INITIALIZER(image_sources);
unsigned int image_source_count;

static TAILQ_HEAD(, image_channel) image_channels =
    TAILQ_HEAD_INITIALIZER(image_channels);
unsigned int image_channel_count;

/*
 * image_retain --
 *	Retain (increment the refcnt) on the specified image.
 */
static void
image_retain(struct nabu_image *img)
{
	img->refcnt++;
	assert(img->refcnt != 0);
}

/*
 * image_release --
 *	Release the specified image.
 */
static void
image_release(struct nabu_image *img)
{
	assert(img->refcnt > 0);
	if (img->refcnt-- == 1) {
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
 * image_source_alloc --
 *	Allocate a new image source.
 */
static struct image_source *
image_source_alloc(char *name, image_source_type type)
{
	if (image_source_lookup(name) != NULL) {
		log_error("Image source %s alreadty exists.", name);
		goto bad;
	}

	struct image_source *imgsrc = calloc(1, sizeof(*imgsrc));
	if (imgsrc != NULL) {
		imgsrc->name = name;
		imgsrc->type = type;
	} else {
		log_error("Unable to allocate image source descriptor for %s",
		    name);
		goto bad;
	}
	return imgsrc;
 bad:
	free(name);
	return NULL;
}

/*
 * image_add_local_source --
 *	Add a local image source.
 */
void
image_add_local_source(char *name, char *path)
{
	struct image_source *imgsrc =
	    image_source_alloc(name, IMAGE_SOURCE_LOCAL);
	if (imgsrc != NULL) {
		imgsrc->root = path;
		LIST_INSERT_HEAD(&image_sources, imgsrc, link);
		image_source_count++;
		log_info("Adding Local source %s at %s",
		    imgsrc->name, imgsrc->root);
	} else {
		/* Error already logged. */
		free(path);
	}
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
		chan = NULL;
		goto bad;
	}

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
 * image_load_file --
 *	Load the specified file.  Caller is responsible for
 *	freeing the buffer.
 */
uint8_t *
image_load_file(const char *path, size_t *filesizep, size_t extra)
{
	struct stat sb;
	uint8_t *filebuf = NULL;
	size_t filesize = 0;
	int fd = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("open(%s): %s", path, strerror(errno));
		goto bad;
	}

	if (fstat(fd, &sb) < 0) {
		log_error("fstat(%s): %s", path, strerror(errno));
		goto bad;
	}
	if (!S_ISREG(sb.st_mode)) {
		log_error("%s is not a regular file.", path);
		goto bad;
	}

	filesize = (size_t)sb.st_size;
	filebuf = malloc(filesize + extra);
	if (filebuf == NULL) {
		log_error("Unable to allocate %zu bytes for %s",
		    filesize + extra, path);
		goto bad;
	}

	if (read(fd, filebuf, filesize) != (ssize_t)filesize) {
		log_error("Unable to read %s", path);
		goto bad;
	}
 out:
	if (fd >= 0) {
		close(fd);
	}
	*filesizep = filesize;
	return filebuf;
 bad:
	if (filebuf != NULL) {
		free(filebuf);
		filebuf = NULL;
	}
	goto out;
}

static pthread_mutex_t image_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static size_t image_cache_size;

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
			image_retain(img);
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

/*
 * image_pak_name --
 *	Generate a NabuRetroNet PAK name from the given image number.
 */
static char *
image_pak_name(uint32_t image)
{
	char namestr[sizeof("000001nabu")];
	MD5_CTX ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char pakname[PAK_NAME_SIZE];

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
}

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

/*
 * image_decrypt_pak --
 *	Decrypt a PAK image.
 */
static bool
image_decrypt_pak(const uint8_t *src, uint8_t *dst, size_t len)
{
#ifdef __APPLE__
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
#else /* ! __APPLE__ */
	DES_cblock iv = NABU_PAK_IV;
	DES_cblock key = NABU_PAK_KEY;
	DES_key_schedule ks;

	DES_set_key_unchecked(&key, &ks);
	DES_ncbc_encrypt((const unsigned char *)src,
	    (unsigned char *)dst, (long)len, &ks, &iv, 0);

	return true;
#endif /* __APPLE__ */
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

/*
 * image_load_image_from_path --
 *	Load an image from the specified path.
 */
static struct nabu_image *
image_load_image_from_path(struct image_channel *chan, uint32_t image,
    const char *path)
{
	uint8_t *filebuf;
	size_t filesize;
	struct nabu_image *img;

	filebuf = image_load_file(path, &filesize, 0);
	if (filebuf == NULL) {
		return NULL;
	}

	if (chan->type == IMAGE_CHANNEL_PAK) {
		img = image_from_pak(chan, image, filebuf, filesize);
		free(filebuf);
	} else {
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
 * image_load --
 *	Load the specified segment.
 */
struct nabu_image *
image_load(struct nabu_connection *conn, uint32_t image)
{
	char image_path[PATH_MAX];
	char *fname;
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
		log_debug("[%s] Channel cache hit for image %06X: %s",
		    conn->name, image, img->name);
		return img;
	}

	if (conn->channel->type == IMAGE_CHANNEL_PAK) {
		fname = image_pak_name(image);
		imgtype = "pak";
	} else {
		fname = image_nabu_name(image);
		imgtype = "nabu";
	}

	snprintf(image_path, sizeof(image_path), "%s/%s", conn->channel->path,
	    fname);
	log_debug("[%s] Loading %s-%06X from %s", conn->name, imgtype, image,
	    image_path);
	free(fname);

	img = image_load_image_from_path(conn->channel, image, image_path);
	if (img != NULL) {
		img = image_cache_insert(conn->channel, img);
		if (conn->last_image != NULL) {
			image_release(conn->last_image);
		}
		conn->last_image = img;
		return img;
	}

	return NULL;
}

/*
 * image_done --
 *	Indicate that the connection is done with it's
 *	cached image.
 */
void
image_done(struct nabu_connection *conn, struct nabu_image *img)
{
	assert(img != NULL);
	if (img == conn->last_image) {
		conn->last_image = NULL;
		image_release(img);
	}
}
