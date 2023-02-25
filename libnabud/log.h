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

#ifndef log_h_included
#define	log_h_included

#include <stdbool.h>
#include <stdio.h>

typedef enum {
	LOG_TYPE_INFO	= 0,
	LOG_TYPE_DEBUG	= 1,
	LOG_TYPE_ERROR	= 2,
	LOG_TYPE_FATAL	= 3,
} log_type;

/* This is mainly for debug messages. */
typedef enum {
	LOG_SUBSYS_ANY		= -1,

	LOG_SUBSYS_ATOM		= 0,
	LOG_SUBSYS_CLI,
	LOG_SUBSYS_CONN_IO,
	LOG_SUBSYS_FILEIO,

	LOG_SUBSYS_ADAPTOR,
	LOG_SUBSYS_CONTROL,
	LOG_SUBSYS_CONN,
	LOG_SUBSYS_IMAGE,
	LOG_SUBSYS_NHACP,
	LOG_SUBSYS_RETRONET,
	LOG_SUBSYS_STEXT,

	LOG_NSUBSYS
} log_subsys;

#define	LOG_OPT_FOREGROUND	(1U << 0)
#define	LOG_OPT_DEBUG		(1U << 1)

bool	log_init(const char *, unsigned int);
void	log_message(log_type, log_subsys, const char *, const char *, ...)
	    __attribute__((__format__(__printf__, 4, 5)));
void	log_fini(void);

bool	log_debug_enable(const char *);
void	log_subsys_list(FILE *, const char *);

#define	log_info(...)		\
	log_message(LOG_TYPE_INFO, LOG_SUBSYS_ANY, __func__, __VA_ARGS__)
#define	log_debug(s, ...)		\
	log_message(LOG_TYPE_DEBUG, (s), __func__, __VA_ARGS__)
#define	log_error(...)		\
	log_message(LOG_TYPE_ERROR, LOG_SUBSYS_ANY, __func__, __VA_ARGS__)
#define	log_fatal(...)		\
	/* This one doesn't return; trick the compiler */		\
	for (log_message(LOG_TYPE_FATAL, LOG_SUBSYS_ANY, __func__,	\
			 __VA_ARGS__);;)

#endif /* log_h_included */
