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
 * Logging functions.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include "log.h"

bool		debug;

static const char *log_typenames[] = {
	[LOG_TYPE_INFO]		=	"INFO",
	[LOG_TYPE_DEBUG]	=	"DEBUG",
	[LOG_TYPE_ERROR]	=	"ERROR",
	[LOG_TYPE_FATAL]	=	"FATAL",
};

#define	log_type_is_valid(t)	((t) >= LOG_TYPE_INFO && (t) <= LOG_TYPE_FATAL)

void
log_message(log_type type, const char *func, const char *fmt, ...)
{
	va_list ap;
	char *caller_string = NULL;

	assert(log_type_is_valid(type));

	if (type == LOG_TYPE_DEBUG && !debug) {
		return;
	}

	va_start(ap, fmt);
	vasprintf(&caller_string, fmt, ap);
	va_end(ap);

	/* XXX Add support for sending to syslog. */

	printf("%s: %s: %s\n", log_typenames[type], func, caller_string);
	free(caller_string);

	if (type == LOG_TYPE_FATAL) {
		abort();
	}
}
