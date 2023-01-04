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
 * Support for NabuRetroNet features / extensions.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "conn.h"
#include "fileio.h"
#include "log.h"
#include "retronet.h"

#if 0
/*
 * rn_file_insert --
 *	Insert a file into the list, allocating a slot number if
 *	necessary.  This always succeeds, and returns the old
 *	file object that needs to be freed if there's a collision.
 */
static bool
rn_file_insert(struct nabu_connection *conn, struct rn_file *f,
    uint8_t reqslot, struct rn_file **oldfp)
{
	struct rn_file *lf, *prevf = NULL;
	uint8_t slot;

	*oldfp = NULL;

	if (reqslot == 0xff) {
		/*
		 * We're being asked to allocate a slot #.  Find the
		 * lowest slot number and use that.
		 */
		slot = 0;
		LIST_FOREACH(lf, &conn->rn_files, link) {
			assert(lf->slot != 0xff);
			assert(slot <= lf->slot);
			if (slot < lf->slot) {
				f->slot = slot;
				LIST_INSERT_BEFORE(lf, f, link);
				return true;
			}
			slot = lf->slot + 1;
			if (slot == 0xff) {
				/*
				 * The connection is using 255 slots
				 * slots.  The protocol has no provision
				 * for failure, but this situation is
				 * absurd.  Instead, this implementation
				 * treats this situation as a failure
				 * and treats slot 255 as a dead file.
				 */
				return false;
			}
			prev = lf;
		}
		goto insert_after;
	}

	/*
	 * We're being asked to allocate a specific slot, possibly
	 * replacing another file.
	 */
	slot = reqslot;
	LIST_FOREACH(lf, &conn->rn_files, link) {
		if (slot > lf->slot) {
			prevf = lf;
			continue;
		}
		if (slot == lf->slot) {
			LIST_REMOVE(lf, link);
			*oldfp = lf;
			if (prevf != NULL) {
				LIST_INSERT_AFTER(prevf, f, link);
			} else {
				LIST_INSERT_HEAD(&conn->rn_files, f, link);
				assert((lf = LIST_NEXT(f, link)) == NULL ||
				       lf->slot > f->slot);
			}
			return true;
		}
		if (slot < lf->slot) {
			f->slot = slot;
			LIST_INSERT_BEFORE(lf, f, link);
			return true;
		}
	}
 insert_after:
	f->slot = slot;
	if (prevf != NULL) {
		LIST_INSERT_AFTER(prevf, f, link);
	} else {
		LIST_INSERT_HEAD(&conn->rn_files, f, link);
	}
	assert((lf = LIST_NEXT(f, link)) == NULL || lf->slot > f->slot);
	return true;
}
#endif

/*
 * rn_file_closeall --
 *	Close all files associated with this connection.
 */
void
rn_file_closeall(struct nabu_connection *conn)
{
}
