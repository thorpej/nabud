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
 
// need this for cygwin compiles
#ifdef __CYGWIN__
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "log.h"
#include "missing.h"

/* XXX use syslog_r(3) if available. */
#include <pthread.h>
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t log_syslog_init_once = PTHREAD_ONCE_INIT;
static bool log_using_syslog;

static unsigned int log_options;
static FILE *log_file;

static const char *log_typenames[] = {
	[LOG_TYPE_INFO]		=	"INFO",
	[LOG_TYPE_DEBUG]	=	"DEBUG",
	[LOG_TYPE_ERROR]	=	"ERROR",
	[LOG_TYPE_FATAL]	=	"FATAL",
};

static const int log_type_to_syslog[] = {
	[LOG_TYPE_INFO]		=	LOG_INFO,
	[LOG_TYPE_DEBUG]	=	LOG_DEBUG,
	[LOG_TYPE_ERROR]	=	LOG_ERR,
	[LOG_TYPE_FATAL]	=	LOG_ERR,
};

#define	log_type_is_valid(t)	((t) >= LOG_TYPE_INFO && (t) <= LOG_TYPE_FATAL)

#define _GNU_SOURCE

/*
 * log_syslog_init --
 *	Initialize our interface to syslog.  Just once.
 */
static void
log_syslog_init(void)
{
	pthread_mutex_lock(&log_lock);
	openlog(getprogname(), LOG_NDELAY | LOG_PID, LOG_USER);
	log_using_syslog = true;
	pthread_mutex_unlock(&log_lock);
}

/*
 * log_init --
 *	Initialize the logging interface.
 */
bool
log_init(const char *path, unsigned int options)
{
	log_options = options;

	/* If we're in the foreground, always log to stdout. */
	if (log_options & LOG_OPT_FOREGROUND) {
		log_file = stdout;
		return true;
	}

	/* If the caller specified a path, log there. */
	if (path != NULL) {
		FILE *fp = fopen(path, "a");
		if (fp == NULL) {
			fprintf(stderr, "%s: Unable to open log file %s: %s",
			    getprogname(), path, strerror(errno));
			return false;
		}
		log_file = fp;
		return true;
	}

	/*
	 * We will be using syslog() -- initialization will be deferred
	 * until the first message has been sent.
	 */
	return true;
}

/*
 * log_fini --
 *	Finish using the logging interface.
 */
void
log_fini(void)
{
	pthread_mutex_lock(&log_lock);
	if (log_using_syslog) {
		closelog();
	}
	pthread_mutex_unlock(&log_lock);
}

/*
 * log_message --
 *	Log a message.  This is usually invoked via the macros
 *	for specific log message types.
 */

void
log_message(log_type type, const char *func, const char *fmt, ...)
{
	va_list ap;
	char *caller_string = NULL;
	int rv;

	assert(log_type_is_valid(type));

	if (type == LOG_TYPE_DEBUG &&
	    (log_options & LOG_OPT_DEBUG) == 0) {
		return;
	}

	va_start(ap, fmt);
	rv = vasprintf(&caller_string, fmt, ap);
	va_end(ap);

	if (rv == -1) {
		return;
	}

	if (log_file) {
		fprintf(log_file, "%s: %s: %s\n", log_typenames[type],
		    func, caller_string);
		fflush(log_file);
	} else {
		pthread_once(&log_syslog_init_once, log_syslog_init);
		pthread_mutex_lock(&log_lock);
		syslog(log_type_to_syslog[type], "%s: %s: %s",
		    log_typenames[type], func, caller_string);
		pthread_mutex_unlock(&log_lock);
	}
	free(caller_string);

	if (type == LOG_TYPE_FATAL) {
		abort();
	}
}
