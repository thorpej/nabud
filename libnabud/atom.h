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

#ifndef atom_h_included
#define	atom_h_included

#include <stdbool.h>
#include <stdint.h>

#include "conn_io.h"
#include "nabuctl_proto.h"
#include "nbsd_queue.h"

struct atom {
	TAILQ_ENTRY(atom) link;
	struct nabuctl_atom_header hdr;
	union {
		void *external_data;
		uint8_t inline_data[sizeof(void *)];
	};
};

#define	ATOM_DATA(atom)							\
	(ATOM_DATA_INLINE_P((atom)->hdr.tag) ? (atom)->inline_data	\
					     : (atom)->external_data)

#define	ATOM_DATA_INLINE_P(tag)						\
	(NABUCTL_TYPE(tag) == NABUCTL_TYPE_BOOL)

struct atom_list {
	TAILQ_HEAD(, atom) list;
	unsigned int count;
};

uint32_t	atom_data_type(struct atom *);
uint32_t	atom_tag(struct atom *);
size_t		atom_length(struct atom *);
void *		atom_consume(struct atom *);
void *		atom_dataref(struct atom *);
uint64_t	atom_number_value(struct atom *);
bool		atom_bool_value(struct atom *);

const char *	atom_typedesc(uint32_t);
const char *	atom_objdesc(uint32_t);

void		atom_list_init(struct atom_list *);
void		atom_list_free(struct atom_list *);
bool		atom_list_append(struct atom_list *, uint32_t,
		    const void *, size_t);
bool		atom_list_append_string(struct atom_list *, uint32_t,
		    const char *);
bool		atom_list_append_number(struct atom_list *, uint32_t, uint64_t);
bool		atom_list_append_bool(struct atom_list *, uint32_t, bool);
bool		atom_list_append_void(struct atom_list *, uint32_t);
bool		atom_list_append_done(struct atom_list *);
bool		atom_list_append_error(struct atom_list *);
unsigned int	atom_list_count(struct atom_list *);
struct atom *	atom_list_next(struct atom_list *, struct atom *);

void		atom_send_error(struct conn_io *);

bool		atom_list_send(struct conn_io *, struct atom_list *);
bool		atom_list_recv(struct conn_io *, struct atom_list *);

#endif /* atom_h_included */
