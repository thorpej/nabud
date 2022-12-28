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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/des.h>
#include <openssl/md5.h>

#include "conn.h"
#include "image.h"
#include "log.h"

static const char *images_directory;

/*
 * image_load_file --
 *	Load the specified file.  Caller is responsible for
 *	freeing the buffer.
 */
static uint8_t *
image_load_file(const char *path, size_t *filesizep)
{
	struct stat sb;
	uint8_t *filebuf = NULL;
	size_t filesize;
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
	filebuf = malloc(filesize);
	if (filebuf == NULL) {
		log_error("Unable to allocate %zu bytes for %s",
		    filesize, path);
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
        unsigned char digest[MD5_DIGEST_LENGTH];
	char pakname[PAK_NAME_SIZE];

        snprintf(namestr, sizeof(namestr), "%06Xnabu", image);
        MD5((unsigned char *)namestr, sizeof(namestr) - 1, digest);
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
image_from_nabu(uint32_t image, uint8_t *filebuf, size_t filesize)
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

	img->name = strdup(image_name);
	img->data = filebuf;
	img->length = filesize;
	img->number = image;
	img->refcnt = 1;
	img->is_pak = false;

	return img;
}

/*
 * image_from_pak --
 *	Create an image descriptor from the provided PAK buffer.
 */
static struct nabu_image *
image_from_pak(uint32_t image, const uint8_t *pakbuf, size_t paklen)
{
	DES_cblock iv = NABU_PAK_IV;
	DES_cblock key = NABU_PAK_KEY;
	DES_key_schedule ks;
	char image_name[sizeof("pak-000001")];

	snprintf(image_name, sizeof(image_name), "pak-%06X", image);

	if ((paklen % sizeof(DES_cblock)) != 0) {
		log_error("%s size %zu is not a multiple of DES block size.",
		    image_name, paklen);
		return NULL;
	}

	DES_set_key_unchecked(&key, &ks);

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

	DES_ncbc_encrypt((const unsigned char *)pakbuf,
	    (unsigned char *)pakdata, (long)paklen, &ks, &iv, 0);

	img->name = strdup(image_name);
	img->data = pakdata;
	img->length = paklen;
	img->number = image;
	img->refcnt = 1;
	img->is_pak = true;

	return img;
}

/*
 * image_load_image_from_path --
 *	Load an image from the specified path.
 */
static struct nabu_image *
image_load_image_from_path(uint32_t image, const char *path, bool is_pak)
{
	uint8_t *filebuf;
	size_t filesize;
	struct nabu_image *img;

	filebuf = image_load_file(path, &filesize);
	if (filebuf == NULL) {
		return NULL;
	}

	if (is_pak) {
		img = image_from_pak(image, filebuf, filesize);
		free(filebuf);
	} else {
		img = image_from_nabu(image, filebuf, filesize);
	}

	return img;
}

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
	char image_path[PATH_MAX];
	char *fname;
	struct nabu_image *img;

	if ((img = conn->last_image) != NULL && img->number == image) {
		/* Cache hit! */
		log_debug("[%s] Cache hit for image %06X: %s", conn->name,
		    image, img->name);
		return img;
	}

	/* Try loading a .nabu image first. */
	fname = image_nabu_name(image);
	snprintf(image_path, sizeof(image_path), "%s/%s",
	    images_directory, fname);
	log_debug("[%s] Loading NABU-%06X from %s", conn->name, image,
	    image_path);
	free(fname);

	img = image_load_image_from_path(image, image_path, false);
	if (img != NULL) {
		if (conn->last_image != NULL) {
			image_release(conn->last_image);
		}
		conn->last_image = img;
		return img;
	}

	/* Not found -- try a PAK. */
	fname = image_pak_name(image);
	snprintf(image_path, sizeof(image_path), "%s/%s",
	    images_directory, fname);
	log_debug("[%s] Loading PAK-%06X from %s", conn->name, image,
	    image_path);
	free(fname);

	img = image_load_image_from_path(image, image_path, true);
	if (img != NULL) {
		if (conn->last_image != NULL) {
			image_release(conn->last_image);
		}
		conn->last_image = img;
		return img;
	}

	return NULL;
}

/*
 * image_release --
 *	Release the specified segment.
 */
void
image_release(struct nabu_image *img)
{
	assert(img->refcnt > 0);
	if (img->refcnt-- == 1) {
		free(img->name);
		free(img->data);
		free(img);
	}
}
