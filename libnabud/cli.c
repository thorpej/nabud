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

/*
 * Command line tool helper functions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBEDIT_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "cli.h"
#include "log.h"

#define	MAXARGV		8

static jmp_buf		cli_quit_env;
static jmp_buf		cli_except_env;
static bool		cli_except_env_use;

/*
 * cli_quit --
 *	Throw a "quit" exception.
 */
void
cli_quit(void)
{
	longjmp(cli_quit_env, 1);
}

/*
 * cli_throw --
 *	Throw a general exception that puts us back into the
 *	main command loop.
 */
void
cli_throw(void)
{
	if (cli_except_env_use) {
		longjmp(cli_except_env, 1);
	} else {
		abort();
	}
}

/*
 * cli_handle_exitsig --
 *	Signal handler for signals-that-cause-exit.
 */
static void
cli_handle_exitsig(int signo)
{
	cli_quit();
}

/*
 * cli_cmdtab_lookup --
 *	Lookup an entry in a command table.
 */
const struct cmdtab *
cli_cmdtab_lookup(const struct cmdtab *tab, const char *name)
{
	const struct cmdtab *cmd, *first_match = NULL;
	size_t namelen = strlen(name);
	size_t cmdlen;
	bool collision = false;

	for (cmd = tab; cmd->name != NULL; cmd++) {
		cmdlen = strlen(cmd->name);
		if (namelen > cmdlen) {
			continue;
		}
		if (cmdlen == namelen && strcmp(name, cmd->name) == 0) {
			return cmd;
		}
		if (strncmp(name, cmd->name, namelen) == 0) {
			if (first_match == NULL) {
				first_match = cmd;
			} else {
				collision = true;
			}
		}
	}
	return (first_match == NULL || collision) ? cmd : first_match;
}

/*
 * cli_help --
 *	Help helper.
 */
bool
cli_help(const struct cmdtab *cmdtab)
{
	printf("Available commands:\n");
	return cli_help_list(cmdtab);
}

/*
 * cli_help_list --
 *	Another help helper.
 */
bool
cli_help_list(const struct cmdtab *cmdtab)
{
	const struct cmdtab *cmd;

	for (cmd = cmdtab; cmd->name != NULL; cmd++) {
		if (! cmd->suppress_in_help) {
			printf("\t%s\n", cmd->name);
		}
	}
	return false;
}

/*
 * cli_command_unknown --
 *	Called when an unknown / unrecognized command is entered
 *	at the top-level.
 */
bool
cli_command_unknown(int argc, char *argv[])
{
	printf("Unknown command: '%s'.  Try 'help'.\n", argv[0]);
	return false;
}

#ifdef HAVE_LIBEDIT_READLINE
static bool libedit_readline_initialized = false;

/*
 * cli_command_completion_generator --
 *	Command completion match generator.
 */
static char *
cli_command_completion_generator(const char *text, int state)
{
	return NULL;
}

/*
 * cli_command_completion --
 *	Command completion callback.
 */
static char **
cli_command_completion(const char *text, int start, int end)
{
	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, cli_command_completion_generator);
}
#endif /* HAVE_LIBEDIT_READLINE */

/*
 * cli_commands --
 *	CLI command loop.
 */
void
cli_commands(const char *prompt, const struct cmdtab *cmdtab,
    bool (*prepfunc)(void *), void *ctx)
{
	const struct cmdtab *cmd;
	char *line = NULL, *cp, *tok;
	char *argv[MAXARGV];
	int argc;
	bool all_done;
	char *promptstr = NULL;
#ifndef HAVE_LIBEDIT_READLINE
	ssize_t linelen;
	size_t zero;
#endif

#ifdef HAVE_LIBEDIT_READLINE
	if (! libedit_readline_initialized) {
		using_history();
		libedit_readline_initialized = true;
	}
	rl_attempted_completion_function = cli_command_completion;
#endif

	if (asprintf(&promptstr, "%s> ", prompt) < 0) {
		log_error("Unable to allocate memory.");
		abort();
	}

	if (setjmp(cli_quit_env)) {
		goto quit;
	}

	/* cli_handle_exitsig() is now safe. */
	(void) signal(SIGINT, cli_handle_exitsig);

	/*
	 * Now that the command processing environment is set up,
	 * perform any setup needed before we actually process
	 * commands.
	 */
	if (prepfunc != NULL && !(*prepfunc)(ctx)) {
		/* Error already displayed. */
		goto out;
	}

	for (all_done = false;;) {
 nextline:
		if (line != NULL) {
			free(line);
			line = NULL;
		}
		if (all_done) {
			goto out;		/* quiet return */
		}
#ifdef HAVE_LIBEDIT_READLINE
		line = readline(promptstr);
		if (line == NULL) {
			goto quit;		/* got EOF */
		}
		add_history(line);
#else
		fprintf(stdout, "%s", promptstr);
		fflush(stdout);
		zero = 0;
		linelen = getline(&line, &zero, stdin);
		if (linelen < 0) {
			goto quit;		/* got EOF */
		}
		line[linelen - 1] = '\0';	/* get rid of the newline */
#endif /* HAVE_LIBEDIT_READLINE */

		/* Break it into tokens. */
		argc = 0;
		cp = line;
		while ((tok = strtok(cp, " \t")) != NULL) {
			cp = NULL;
			if (argc == MAXARGV) {
				printf("Too many command arguments.\n");
				goto nextline;	/* double-break, sigh */
			}
			argv[argc++] = tok;
		}

		if (argc == 0) {
			continue;
		}
		cmd = cli_cmdtab_lookup(cmdtab, argv[0]);
		assert(cmd != NULL);

		cli_except_env_use = true;
		if (setjmp(cli_except_env)) {
			all_done = false;
		} else {
			all_done = (*cmd->func)(argc, argv);
		}
		cli_except_env_use = false;
	}

 quit:
	printf("Quit!\n");
 out:
	if (promptstr != NULL) {
		free(promptstr);
	}
	if (line != NULL) {
		free(line);
	}
}

/*
 * cli_subcommand --
 *	Call a sub-command.
 */
bool
cli_subcommand(const struct cmdtab *tab, int argc, char *argv[], int offset)
{
	const struct cmdtab *cmd;

	assert(offset >= 0);
	cmd = cli_cmdtab_lookup(tab, argv[offset]);
	assert(cmd != NULL);

	return (*cmd->func)(argc, argv);
}
