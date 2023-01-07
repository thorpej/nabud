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

#ifndef retronet_h_included
#define	retronet_h_included

#include <stdbool.h>
#include <stdint.h>

#include "nbsd_queue.h"

struct rn_file {
	LIST_ENTRY(rn_file) link;
	struct fileio	*file;
	uint8_t		slot;

	uint8_t		*shadow_data;
	size_t		shadow_len;
};

struct nabu_connection;

uint8_t		rn_api_file_open(struct nabu_connection *, const char *,
				 uint16_t, uint8_t);
void		rn_api_fh_close(struct nabu_connection *, uint8_t);
int32_t		rn_api_fh_size(struct nabu_connection *, uint8_t);
void		rn_api_fh_read(struct nabu_connection *, uint8_t,
			       void *, uint32_t, uint16_t);
void		rn_api_fh_append(struct nabu_connection *, uint8_t,
				 void *, uint16_t);
void		rn_api_fh_replace(struct nabu_connection *, uint8_t,
				  void *, uint32_t, uint16_t);
void		rn_api_fh_insert(struct nabu_connection *, uint8_t,
				 void *, uint32_t, uint16_t);
void		rn_api_fh_delete_range(struct nabu_connection *, uint8_t,
				       uint32_t, uint16_t);
void		rn_api_fh_truncate(struct nabu_connection *, uint8_t);

void		rn_file_closeall(struct nabu_connection *);

#endif /* retronet_h_included */
