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

#ifndef missing_h_included
#define	missing_h_included

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Elide some open(2) flags that might not exist on some systems.
 */
#ifndef HAVE_O_TEXT
#define	O_TEXT		0		/* this is a Windows thing */
#endif /* ! HAVE_O_TEXT */

#ifndef HAVE_O_BINARY
#define	O_BINARY	0		/* this is a Windows thing */
#endif /* ! HAVE_O_BINARY */

#ifndef HAVE_O_NOCTTY
#define	O_NOCTTY	0
#endif /* ! HAVE_O_NOCTTY */

#ifndef HAVE_GETPROGNAME
const char *	getprogname(void);
void		setprogname(const char *);
#endif /* ! HAVE_GETPROGNAME */

#ifndef HAVE_STRLCPY
size_t		strlcpy(char *, const char *, size_t);
#endif /* ! HAVE_STRLCPY */

#endif /* missing_h_included */
