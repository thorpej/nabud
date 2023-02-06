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

#ifndef stext_h_included
#define	stext_h_included

/* 1MB limit on shadow file length. */
#define	MAX_SHADOW_LENGTH	(1U * 1024 * 1024)

/* 32-bit limit on fileio file length (due to wire protocol). */
#define	MAX_FILEIO_LENGTH	UINT32_MAX

struct fileio_attrs;
struct nabu_connection;

struct stext_context {
	struct nabu_connection *conn;
	LIST_HEAD(, stext_file) files;
};

struct stext_file {
	LIST_ENTRY(stext_file) link;
	uint8_t		slot;
	const struct stext_fileops *ops;

	union {
		struct {
			struct fileio	*fileio;
		} fileio;
		struct {
			uint8_t		*data;
			size_t		length;
		} shadow;
	};
};

struct stext_fileops {
	int	(*file_read)(struct stext_file *, void *, uint32_t, uint16_t *);
	int	(*file_write)(struct stext_file *, const void *, uint32_t,
		    uint16_t);
	void	(*file_close)(struct stext_file *);
};

extern const struct stext_fileops stext_fileops_fileio;
extern const struct stext_fileops stext_fileops_shadow;

bool	stext_file_insert(struct stext_context *, struct stext_file *,
	    uint8_t, struct stext_file **);
struct stext_file *stext_file_find(struct stext_context *, uint8_t);
void	stext_context_init(struct stext_context *, struct nabu_connection *);
void	stext_context_fini(struct stext_context *);

int	stext_file_open(struct stext_context *, const char *, uint8_t,
	    struct fileio_attrs *, struct stext_file **);
void	stext_file_close(struct stext_file *);

static inline int
stext_file_read(struct stext_file *f, void *vbuf, uint32_t offset,
    uint16_t *lengthp)
{
	return (*f->ops->file_read)(f, vbuf, offset, lengthp);
}

static inline int
stext_file_write(struct stext_file *f, const void *vbuf, uint32_t offset,
    uint16_t length)
{
	return (*f->ops->file_write)(f, vbuf, offset, length);
}

#endif /* stext_h_included */
