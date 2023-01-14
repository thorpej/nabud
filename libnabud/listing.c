/*-             
 * Copyright (c) 2023 Jason R. Thorpe.
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
 * Support for parsing a NabuRetroNet listing file.
 *
 * N.B. the listing data is modified in-place and the returned
 * listing structure references the listing data blob.
 */

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>

#include "listing.h"
#include "log.h"

struct parser_context {
	char *cur;
	struct listing_category *current_category;
	struct listing *listing;
	jmp_buf alloc_fail_env;
};

static void *
listing_alloc_internal(struct parser_context *ctx, size_t size)
{
	void *v = calloc(1, size);
	if (v == NULL) {
		longjmp(ctx->alloc_fail_env, 1);
	}
	return v;
}

static struct listing *
listing_alloc(struct parser_context *ctx)
{
	return listing_alloc_internal(ctx, sizeof(struct listing));
}

static struct listing_category *
category_alloc(struct parser_context *ctx)
{
	return listing_alloc_internal(ctx, sizeof(struct listing_category));
}

static struct listing_entry *
entry_alloc(struct parser_context *ctx)
{
	return listing_alloc_internal(ctx, sizeof(struct listing_entry));
}

static void
zero_back(char *cp, char *limit)
{
	while (cp > limit && isspace((unsigned char)*cp)) {
		*cp-- = '\0';
	}
}

static void
parse_category(struct parser_context *ctx)
{
	/*
	 * Category entry looks like this:
	 *
	 *	:RetroNet
	 */
	char *name, *cp;

	assert(*ctx->cur == ':');

	name = cp = ctx->cur + 1;

	/* Find the end of the line. */
	cp += strcspn(cp, "\n");

	/* Advance the cursor to the next line. */
	if (*(ctx->cur = cp) == '\n') {
		ctx->cur++;
	}

	/* Walk backward, setting NULs until the first non-whitespace. */
	zero_back(cp, name);

	/* If the resulting name is not empty, create the category. */
	if (strlen(name) != 0) {
		struct listing_category *category = category_alloc(ctx);
		TAILQ_INIT(&category->entries);
		category->name = name;

		TAILQ_INSERT_TAIL(&ctx->listing->categories, category, link);
		ctx->current_category = category;
	}
}

static void
parse_entry(struct parser_context *ctx)
{
	/*
	 * File entry looks like this:
	 *
	 *	HelloNABUBounce.nabu ; Hello NABU Bounce
	 */
	char *name, *desc, *limit, *cp;

	assert(ctx->current_category != NULL);

	name = cp = limit = ctx->cur;
	desc = NULL;

	/*
	 * Find the description delimeter or the end of the line.
	 */
	cp += strcspn(cp, ";\n");

	if (*cp == ';') {
		desc = cp + 1;

		/* Skip whitespace. */
		while (isspace((unsigned char)*desc)) {
			desc++;
		}
		limit = desc;

		/* Zero back to the end of the name. */
		*cp++ = '\0';
		zero_back(cp - 2, name);

		/* Find the end of the line. */
		cp += strcspn(cp, "\n");

		/* Ignore empty description. */
		if (strlen(desc) == 0) {
			desc = NULL;
		}
	}

	/* Advance the cursor to the next line. */
	if (*(ctx->cur = cp) == '\n') {
		ctx->cur++;
	}

	/* Walk backward, setting NULs until the first non-whitespace. */
	zero_back(cp, limit);

	/* If the resulting name is not empty, create the category. */
	size_t namelen = strlen(name);
	if (namelen != 0) {
		struct listing_entry *entry = entry_alloc(ctx);
		entry->name = name;
		entry->desc = desc;

		entry->number = ctx->listing->next_fileno++;
		TAILQ_INSERT_TAIL(&ctx->current_category->entries, entry,
		    category_link);
		TAILQ_INSERT_TAIL(&ctx->listing->entries, entry, listing_link);
		if (namelen > ctx->listing->longest_name) {
			ctx->listing->longest_name = namelen;
		}
	}
}

static void
parse_listing(struct parser_context *ctx)
{
	size_t loc;

	/*
	 * The NabuRetroNet listing file for "HomeBrew" has
	 * entries at the top describing the cycle1 / cycle2
	 * channels.  We don't care about those entries for
	 * our purposes, so we skip everything until we encounter
	 * a cateogry delimeter.
	 */
	loc = strcspn(ctx->cur, ":");
	ctx->cur += loc;

	while (*ctx->cur != '\0') {
		/* Skip whitespace. */
		if (isspace((unsigned char)*ctx->cur)) {
			ctx->cur++;
			continue;
		}
		if (*ctx->cur == ':') {
			/* Category delimiter. */
			parse_category(ctx);
			continue;
		}
		/*
		 * If we don't yet have a category, skip ahead until we
		 * find one.
		 */
		if (ctx->current_category == NULL) {
			loc = strcspn(ctx->cur, ":");
			ctx->cur += loc;
			continue;
		}
		if (*ctx->cur == '!') {
			/* Comment / line separator? */
			loc = strcspn(ctx->cur, "\n");
			ctx->cur += loc;
			continue;
		}
		parse_entry(ctx);
	}
}

struct listing_entry *
listing_entry_lookup(struct listing *l, unsigned int number)
{
	struct listing_entry *e;

	TAILQ_FOREACH(e, &l->entries, listing_link) {
		if (e->number == number) {
			return e;
		}
	}
	return NULL;
}

struct listing *
listing_create(char *data, size_t length)
{
	struct parser_context ctx = {
		.cur = data,
	};

	if (setjmp(ctx.alloc_fail_env)) {
		log_debug("Memory allocation failed.");
		if (ctx.listing != NULL) {
			listing_free(ctx.listing);
		} else {
			free(ctx.listing->data);
		}
		return NULL;
	}

	ctx.listing = listing_alloc(&ctx);
	ctx.listing->data = data;
	ctx.listing->length = length;
	ctx.listing->next_fileno = 1;
	TAILQ_INIT(&ctx.listing->categories);
	TAILQ_INIT(&ctx.listing->entries);

	parse_listing(&ctx);
	return ctx.listing;
}

void
listing_free(struct listing *l)
{
	struct listing_category *c;

	while ((c = TAILQ_FIRST(&l->categories)) != NULL) {
		struct listing_entry *e;

		while ((e = TAILQ_FIRST(&c->entries)) != NULL) {
			TAILQ_REMOVE(&c->entries, e, category_link);
			TAILQ_REMOVE(&l->entries, e, listing_link);
			free(e);
		}
		TAILQ_REMOVE(&l->categories, c, link);
		free(c);
	}
	if (l->data != NULL) {
		free(l->data);
	}
	free(l);
}
