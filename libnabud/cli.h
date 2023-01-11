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

#ifndef cli_h_included
#define	cli_h_included

/*
 * Command line tool helper bits.
 */

#include <stdbool.h>

struct cmdtab {
	const char	*name;
	bool		(*func)(int argc, char *argv[]);
	bool		suppress_in_help;
};

#define	CMDTAB_EOL(unkfunc)	{ .func = (unkfunc),			\
				  .suppress_in_help = true }

const struct cmdtab *cli_cmdtab_lookup(const struct cmdtab *, const char *);
bool	cli_commands(const char *, const struct cmdtab *,
	    bool (*)(void *), void *);
void	cli_throw(void);
void	cli_quit(void);

bool	cli_help(const struct cmdtab *);
bool	cli_help_list(const struct cmdtab *);
bool	cli_subcommand(const struct cmdtab *, int, char *[], int);

bool	cli_command_unknown(int, char *[]);

#endif /* cli_h_included */
