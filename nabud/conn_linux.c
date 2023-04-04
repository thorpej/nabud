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
 * Linux-specific bits for the connection abstraction.
 *
 * Specifically, serial ports.  Linux's (well, glibc's) termios API can't
 * set arbitrary baud rates on serial ports (in no small part because an
 * older version of the Linux kernel's termios support couldn't, either).
 * In order to do that, you have to use the "termios2" interface.  But
 * glibc's termios header files don't match the Linux kernel termios header
 * files, so we need to pull this code out into its own file that doesn't
 * include the standard <termios.h> header.
 *
 * (Sigh, what a mess.)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LINUX_TERMIOS2

#include <linux/termios.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * XXX More Linux winning: Can't include <sys/ioctl.h> for the ioctl(2)
 * XXX prototype because that pulls in things that conflict with the
 * XXX declarations in <linux/termios.h>.
 */
extern int ioctl(int fd, unsigned long request, ...);

#include "libnabud/log.h"
#include "conn.h"
#include "conn_linux.h"

bool
conn_serial_setspeed_linux(int fd, const struct conn_add_args *args)
{
	struct termios2 t2;

	if (ioctl(fd, TCGETS2, &t2) < 0) {
		log_error("[%s] ioctl(TCGETS2) failed: %s", args->port,
		    strerror(errno));
		return false;
	}

	t2.c_cflag &= ~CBAUD;
	t2.c_cflag |= BOTHER;
	t2.c_ispeed = (speed_t)args->baud;
	t2.c_ospeed = (speed_t)args->baud;

	if (ioctl(fd, TCSETS2, &t2) < 0) {
		log_error("[%s] ioctl(TCSETS2) failed: %s", args->port,
		    strerror(errno));
		return false;
	}

	return true;
}

#endif /* HAVE_LINUX_TERMIOS2 */
