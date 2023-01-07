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
 * nabuclient -- a simple client of the NABU Adaptor protocol
 *
 * This exists primarily to test nabud and also to inspect replies
 * from other NABU Adaptor emulators.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <err.h>	/* XXX HAVE_ERR_H-ize, please */
#include <netdb.h>
#include <setjmp.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#define	NABU_PROTO_INLINES

#include "../nabud/nabu_proto.h"

static int	client_sock;
static jmp_buf	quit_env;
static jmp_buf	except_env;

#define	QUIT()		longjmp(quit_env, 1)
#define	THROW()		longjmp(except_env, 1)

static const char nabuclient_version[] = VERSION;

#define	MAXARGV		8

static void
server_disconnected(void)
{
	printf("Server disconnected!\n");
	QUIT();
}

static const uint8_t ack_seq[] = NABU_MSGSEQ_ACK;

static void
nabu_send(const void *vbuf, size_t len)
{
	const uint8_t *buf = vbuf;
	size_t resid;
	ssize_t actual;

	for (resid = len; resid != 0;) {
		actual = write(client_sock, buf, resid);
		if (actual == 0) {
			server_disconnected();
		}
		if (actual < 0) {
			warn("writing to socket");
			THROW();
		}
		buf += actual;
		resid -= actual;
	}
}

static void
nabu_send_byte(uint8_t val)
{
	nabu_send(&val, 1);
}

static void
nabu_send_ack(void)
{
	nabu_send(ack_seq, sizeof(ack_seq));
}

static void
nabu_recv(void *vbuf, size_t len)
{
	uint8_t *buf = vbuf;
	size_t resid;
	ssize_t actual;

	for (resid = len; resid != 0;) {
		actual = read(client_sock, buf, resid);
		if (actual == 0) {
			server_disconnected();
		}
		if (actual < 0) {
			warn("reading from socket");
			THROW();
		}
		buf += actual;
		resid -= actual;
	}
}

static void *
nabu_recv_packet_data(size_t *lenp, uint16_t crc)
{
	uint8_t *pktbuf;
	size_t pktidx = 0;
	uint8_t c;
	uint16_t recv_crc, comp_crc;
	bool have_escape = false;

	pktbuf = malloc(NABU_MAXPACKETSIZE);
	assert(pktbuf != NULL);

	while (pktidx < NABU_MAXPACKETSIZE) {
		nabu_recv(&c, 1);
		if (have_escape) {
			have_escape = false;
			if (c == NABU_MSG_ESCAPE) {
				pktbuf[pktidx++] = NABU_MSG_ESCAPE;
			} else if (c == NABU_MSG_DONE) {
				break;
			} else {
				printf("Received unknown escape byte: $%02X\n",
				    c);
			}
		} else if (c == NABU_MSG_ESCAPE) {
			have_escape = true;
		} else {
			pktbuf[pktidx++] = c;
		}
	}
	if (pktidx < NABU_FOOTERSIZE) {
		printf("RUNT PACKET! (%zu bytes)\n", pktidx);
		goto bad;
	}
	if (pktidx >= NABU_MAXPACKETSIZE) {
		printf("WARNING: SERVER IS AT MAX PACKET SIZE!\n");
	}

	recv_crc = nabu_get_crc(&pktbuf[pktidx - NABU_FOOTERSIZE]);
	comp_crc = nabu_crc_final(nabu_crc_update(pktbuf,
						  pktidx - NABU_FOOTERSIZE,
						  crc));
	printf("Received: %zu byte payload (R-CRC=$%04X C-CRC=$%04X -> %s).\n",
	    pktidx - NABU_FOOTERSIZE,
	    recv_crc, comp_crc, recv_crc == comp_crc ? "OK" : "BAD");
	*lenp = pktidx - NABU_FOOTERSIZE;
	return pktbuf;

 bad:
	free(pktbuf);
	THROW();
}

static void
print_octets(const void *vbuf, size_t len)
{
	const uint8_t *buf = vbuf;

	for (size_t i = 0; i < len; i++) {
		printf("$%02X%c", buf[i], i + 1 == len ? '\n' : ' ');
	}
}

static void
print_reply(const void *vbuf, size_t len)
{
	printf("Reply: ");
	print_octets(vbuf, len);
}

static void
print_expected(const void *vbuf, size_t len)
{
	printf("Expected: ");
	print_octets(vbuf, len);
}

static void
print_pkthdr(const struct nabu_pkthdr *hdr)
{
	printf("Packet header:\n");
	printf("\t      image: %06X\n", nabu_get_uint24_be(hdr->image));
	printf("\tsegment_lsb: $%02X (%u)\n", hdr->segment_lsb,
	    hdr->segment_lsb);
	printf("\t      owner: $%02X (%u)\n", hdr->owner, hdr->owner);
	printf("\t       tier: $%08X\n", nabu_get_uint32_be(hdr->tier));
	printf("\t mystery[0]: $%02X\n", hdr->mystery[0]);
	printf("\t mystery[1]: $%02X\n", hdr->mystery[1]);
	printf("\t       type: $%02X\n", hdr->type);
	printf("\t    segment: $%04X (%u)\n", nabu_get_uint16(hdr->segment),
	    nabu_get_uint16(hdr->segment));
	printf("\t     offset: $%04X (%u)\n", nabu_get_uint16_be(hdr->offset),
	    nabu_get_uint16_be(hdr->offset));
}

static bool
check_reply(bool good)
{
	printf("%s!\n", good ? "OK" : "FAILED");
	return good;
}

static bool
check_sequence(const void *vgot, const void *vexpected, size_t len)
{
	const uint8_t *expected = vexpected;
	const uint8_t *got = vgot;

	for (size_t i = 0; i < len; i++) {
		if (expected[i] != got[i]) {
			print_expected(expected, len);
			return check_reply(false);
		}
	}
	return check_reply(true);
}

static bool
check_byte(const void *vgot, uint8_t val)
{
	return check_sequence(vgot, &val, 1);
}

static bool
check_ack(const void *vgot)
{
	return check_sequence(vgot, ack_seq, sizeof(ack_seq));
}

static bool
check_finished(const void *vgot)
{
	static const uint8_t finished_seq[] = NABU_MSGSEQ_FINISHED;

	return check_sequence(vgot, finished_seq, sizeof(finished_seq));
}

static bool
check_authorized(const void *vgot)
{
	const uint8_t *got = vgot;

	if (*got == NABU_MSG_AUTHORIZED) {
		printf("AUTHORIZED!\n");
		printf("Sending NABU_MSGSEQ_ACK.\n");
		nabu_send_ack();
		return true;
	}
	if (*got == NABU_MSG_UNAUTHORIZED) {
		printf("*** UNAUTHORIZED! ***\n");
		printf("Sending NABU_MSGSEQ_ACK.\n");
		nabu_send_ack();
		THROW();
	}
	printf("*** Unexpected reply ***\n");
	return false;
}

static bool
command_exit(int argc, char *argv[])
{
	return true;			/* EOF! */
}

static bool
command_reset(int argc, char *argv[])
{
	uint8_t reply[2];

	printf("Sending: NABU_MSG_RESET.\n");
	nabu_send_byte(NABU_MSG_RESET);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_ack(reply);

	printf("Expecting: NABU_MSG_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_MSG_CONFIRMED);

	return false;
}

static bool
command_get_channel_status(int argc, char *argv[])
{
	uint8_t reply[2];

	printf("Sending NABU_MSG_GET_STATUS.\n");
	nabu_send_byte(NABU_MSG_GET_STATUS);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	if (! check_ack(reply)) {
		THROW();
	}

	printf("Sending NABU_MSG_CHANNEL_STATUS.\n");
	nabu_send_byte(NABU_MSG_CHANNEL_STATUS);

	printf("Waiting for reply.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_reply(reply[0] == NABU_MSG_HAVE_CHANNEL ||
		    reply[0] == NABU_MSG_NEED_CHANNEL);

	printf("Expecting NABU_MSGSEQ_FINISHED.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_finished(reply);

	return false;
}

static bool
command_get_transmit_status(int argc, char *argv[])
{
	uint8_t reply[2];

	printf("Sending NABU_MSG_GET_STATUS.\n");
	nabu_send_byte(NABU_MSG_GET_STATUS);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	if (! check_ack(reply)) {
		THROW();
	}

	printf("Sending NABU_MSG_TRANSMIT_STATUS.\n");
	nabu_send_byte(NABU_MSG_TRANSMIT_STATUS);

	printf("Expecting NABU_MSGSEQ_FINISHED.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_finished(reply);

	return false;
}

static bool
command_start_up(int argc, char *argv[])
{
	uint8_t reply[2];

	printf("Sending: NABU_MSG_START_UP.\n");
	nabu_send_byte(NABU_MSG_START_UP);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_ack(reply);

	printf("Expecting: NABU_MSG_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_MSG_CONFIRMED);

	return false;
}

static void *
send_packet_request(uint16_t segment, uint32_t image,
    struct nabu_pkthdr *pkthdr, size_t *payload_lenp)
{
	uint8_t reply[2];
	uint8_t msg[4];

	printf("Sending: NABU_MSG_PACKET_REQUEST.\n");
	nabu_send_byte(NABU_MSG_PACKET_REQUEST);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_ack(reply);

	printf("Requesting: segment %u of image %06X\n", segment, image);
	msg[0] = 0;
	nabu_set_uint24(&msg[1], NABU_IMAGE_TIME);
	nabu_send(msg, sizeof(msg));

	printf("Expecting: NABU_MSG_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_MSG_CONFIRMED);

	printf("Expecting: authorization byte.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_authorized(reply);

	printf("Expecing: packet header.\n");
	nabu_recv(pkthdr, sizeof(*pkthdr));
	print_pkthdr(pkthdr);

	uint16_t hdr_crc = nabu_crc_update(pkthdr, sizeof(*pkthdr), 0xffff);

	printf("Expecting: Payload.\n");
	return nabu_recv_packet_data(payload_lenp, hdr_crc);
}

static bool
command_get_time(int argc, char *argv[])
{
	struct nabu_pkthdr pkthdr;
	size_t payload_len;

	struct nabu_time *t = send_packet_request(0, NABU_IMAGE_TIME,
	    &pkthdr, &payload_len);
	if (payload_len != NABU_TIMESTAMPSIZE) {
		printf("Unexpected %u byte reply: ", NABU_TIMESTAMPSIZE);
		print_octets(t, payload_len);
	}
	printf("Server time:\n");
	printf("\t  mystery[0]: $%02X\n", t->mystery[0]);
	printf("\t  mystery[1]: $%02X\n", t->mystery[1]);
	printf("\t  mystery[2]: $%02X\n", t->mystery[2]);
	printf("\t       month: %u\n", t->month);
	printf("\tday of month: %u\n", t->month_day);
	printf("\t        year: %u\n", t->year);
	printf("\t        hour: %u\n", t->hour);
	printf("\t      minute: %u\n", t->minute);
	printf("\t      second: %u\n", t->second);

	return false;
}

static bool
command_get_image(int argc, char *argv[])
{
	return false;
}

static bool
command_change_channel(int argc, char *argv[])
{
	uint8_t msg[2];
	long channel;

	if (argc < 2) {
		printf("Args, bro.\n");
		THROW();
	}

	channel = strtol(argv[1], NULL, 10);
	if (channel < 0 || channel > 0x100) {
		printf("%s, seriously?\n", argv[1]);
		THROW();
	}

	printf("Sending: NABU_MSG_CHANGE_CHANNEL.\n");
	nabu_send_byte(NABU_MSG_CHANGE_CHANNEL);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(msg, sizeof(msg));
	print_reply(msg, sizeof(msg));
	check_ack(msg);

	nabu_set_uint16(msg, (uint16_t)channel);
	printf("Sending: %05ld: ", channel);
	print_octets(msg, sizeof(msg));
	nabu_send(msg, sizeof(msg));

	printf("Expecting: NABU_MSG_CONFIRMED.\n");
	nabu_recv(msg, 1);
	print_reply(msg, 1);
	check_byte(msg, NABU_MSG_CONFIRMED);

	return false;
}

static uint8_t
rn_parse_slot(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > 255) {
		printf("'%s' invalid; must be between 0 - 255\n", cp);
		THROW();
	}
	return (uint8_t)val;
}

static uint32_t
rn_parse_offset(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > 0xffffffff) {
		printf("'%s' invalid offset\n", cp);
		THROW();
	}
	return (uint32_t)val;
}

static uint16_t
rn_parse_length(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > 0xffff) {
		printf("'%s' invalid length\n", cp);
		THROW();
	}
	return (uint16_t)val;
}

static bool
command_rn_file_open(int argc, char *argv[])
{
	uint8_t namelen;
	uint8_t flags[2];
	uint8_t slot;

	if (argc < 3) {
		printf("Args, bro.\n");
		THROW();
	}

	if (strlen(argv[1]) > 255) {
		printf("File name too long: %s\n", argv[1]);
		THROW();
	}
	namelen = strlen(argv[1]);

	if (strcmp(argv[2], "ro") == 0) {
		nabu_set_uint16(flags, 0);
	} else if (strcmp(argv[2], "rw") == 0) {
		nabu_set_uint16(flags, RN_FILE_OPEN_RW);
	} else {
		printf("'%s' invalid; must be 'ro' or 'rw'\n",
		    argv[2]);
		THROW();
	}

	if (argc > 3) {
		slot = rn_parse_slot(argv[3]);
	} else {
		slot = 255;
	}

	printf("Sending: NABU_MSG_RN_FILE_OPEN.\n");
	nabu_send_byte(NABU_MSG_RN_FILE_OPEN);
	printf("Sending: fileNameLen $%02X\n", namelen);
	nabu_send_byte(namelen);
	printf("Sending: fileName: '%s'\n", argv[1]);
	nabu_send(argv[1], namelen);
	printf("Sending: fileFlag: $%02X $%02X\n", flags[0], flags[1]);
	nabu_send(flags, 2);
	printf("Sending: reqSlot: $%02X\n", slot);
	nabu_send_byte(slot);

	printf("Expecting: slot.\n");
	nabu_recv(flags, 1);
	print_reply(flags, 1);

	return false;
}

static bool
command_rn_fh_size(int argc, char *argv[])
{
	uint8_t msg[4];
	uint8_t slot;

	if (argc != 2) {
		printf("Args, bro.\n");
		THROW();
	}

	slot = rn_parse_slot(argv[1]);
	printf("Sending: NABU_MSG_RN_FH_SIZE.\n");
	nabu_send_byte(NABU_MSG_RN_FH_SIZE);
	printf("Sending: slot: $%02X\n", slot);
	nabu_send_byte(slot);

	printf("Expecting: size.\n");
	nabu_recv(msg, 4);
	print_reply(msg, 4);
	printf("Size: %d\n", (int)nabu_get_uint32(msg));

	return false;
}

static bool
command_rn_fh_read(int argc, char *argv[])
{
	uint32_t offset;
	uint16_t length;
	uint8_t msg[7];
	uint8_t buf[65536];

	if (argc < 4) {
		printf("Args, bro.\n");
		THROW();
	}

	msg[0] = rn_parse_slot(argv[1]);
	nabu_set_uint32(&msg[1], (offset = rn_parse_offset(argv[2])));
	nabu_set_uint16(&msg[5], (length = rn_parse_length(argv[3])));

	printf("Sending: NABU_MSG_RN_FH_READ.\n");
	nabu_send_byte(NABU_MSG_RN_FH_READ);
	printf("Sending: slot: $%02X offset: $%02X $%02X $%02X $%02X "
	    "langth: $%02X $%02X\n", msg[0],
	    msg[1], msg[2], msg[3], msg[4],
	    msg[5], msg[6]);
	nabu_send(msg, sizeof(msg));

	printf("Expecting: data.\n");
	nabu_recv(buf, length);

	if (argc >= 5) {
		FILE *fp = fopen(argv[4], "wb");
		if (fp == NULL) {
			printf("Can't open '%s' for saving data.\n", argv[4]);
			THROW();
		}
		printf("Writing data to '%s'.\n", argv[4]);
		fwrite(buf, length, 1, fp);
		fclose(fp);
	}

	return false;
}

static bool
command_rn_fh_close(int argc, char *argv[])
{
	uint8_t slot;

	if (argc != 2) {
		printf("Args, bro.\n");
		THROW();
	}

	slot = rn_parse_slot(argv[1]);
	printf("Sending: NABU_MSG_RN_FH_CLOSE.\n");
	nabu_send_byte(NABU_MSG_RN_FH_CLOSE);
	printf("Sending: slot: $%02X\n", slot);
	nabu_send_byte(slot);

	/* No reply! */

	return false;
}

static bool	command_help(int, char *[]);

static const struct cmdtab {
	const char	*name;
	bool		(*func)(int, char *[]);
} cmdtab[] = {
	{ .name = "exit",		.func = command_exit },
	{ .name = "quit",		.func = command_exit },

	{ .name = "help",		.func = command_help },

	{ .name = "reset",		.func = command_reset },
	{ .name = "start-up",		.func = command_start_up },
	{ .name = "change-channel",	.func = command_change_channel },
	{ .name = "get-channel-status",	.func = command_get_channel_status },
	{ .name = "get-transmit-status",.func = command_get_transmit_status },
	{ .name = "get-time",		.func = command_get_time },
	{ .name = "get-image",		.func = command_get_image },

	/* NabuRetroNet extensions */
	{ .name = "file-open",		.func = command_rn_file_open },
	{ .name = "fh-size",		.func = command_rn_fh_size },
	{ .name = "fh-read",		.func = command_rn_fh_read },
	{ .name = "fh-close",		.func = command_rn_fh_close },

	{ .name = NULL }
};

static bool
command_help(int argc, char *argv[])
{
	const struct cmdtab *cmd;

	printf("Available commands:\n");
	for (cmd = cmdtab; cmd->name != NULL; cmd++) {
		printf("\t%s\n", cmd->name);
	}
	return false;
}

static bool
commands(void)
{
	const struct cmdtab *cmd;
	char *retline, *line = NULL, *cp, *tok;
	size_t linelen;
	char *argv[MAXARGV];
	int argc;
	bool all_done;

	for (all_done = false;;) {
		nextline:
		if (line != NULL) {
			free(line);
			line = NULL;
		}
		if (all_done) {
			return false;
		}
		fprintf(stdout, "nabu> ");
		fflush(stdout);
		retline = fgetln(stdin, &linelen);
		if (retline == NULL) {
			return true;		/* got EOF */
		}

		line = malloc(linelen);
		assert(line != NULL);
		memcpy(line, retline, linelen);
		line[linelen - 1] = '\0';	/* get rid of the newline */

		/* Break it into tokens. */
		argc = 0;
		cp = line;
		while ((tok = strtok(cp, " \t")) != NULL) {
			cp = NULL;
			if (argc == MAXARGV) {
				command_help(argc, argv);
				goto nextline;	/* double-break, sigh */
			}
			argv[argc++] = tok;
		}

		for (cmd = cmdtab; cmd->name != NULL; cmd++) {
			if (strcmp(argv[0], cmd->name) == 0) {
				break;
			}
		}
		if (cmd->name == NULL) {
			printf("Unknown command: %s.  Try 'help'.\n", argv[0]);
		} else {
			if (setjmp(except_env)) {
				all_done = false;
			} else {
				all_done = (*cmd->func)(argc, argv);
			}
		}
	}
}

static void
handle_exitsig(int signo)
{
	QUIT();
}

static void __attribute__((__noreturn__))
usage(void)
{
	fprintf(stderr, "%s version %s\n", getprogname(), nabuclient_version);
	fprintf(stderr, "usage: %s host port\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	struct addrinfo *ai, *ai0;
	int error, sock;

	setprogname(argv[0]);

	if (argc != 3) {
		usage();
		/* NOTREACHED */
	}

	/* Set up our initial signal state. */
	(void) signal(SIGPIPE, SIG_IGN);

	/* Connect to the server. */
	const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_NUMERICSERV,
	};
	char hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
	const char *host, *serv;

	error = getaddrinfo(argv[1], argv[2], &hints, &ai0);
	if (error != 0) {
		errx(EXIT_FAILURE, "Host %s port %s: %s", argv[1], argv[2],
		    gai_strerror(error));
	}

	for (ai = ai0; ai != NULL; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		if (sock < 0) {
			warn("socket(%d, %d, %d)", ai->ai_family,
			    ai->ai_socktype, ai->ai_protocol);
			continue;
		}
		error = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    hostbuf, sizeof(hostbuf), servbuf, sizeof(servbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (error) {
			host = serv = "<unknown>";
		} else {
			host = hostbuf;
			serv = servbuf;
		}
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			warn("connect() to %s port %s", host, serv);
			close(sock);
			continue;
		}
		printf("Connected to %s port %s.\n", host, serv);
		client_sock = sock;

		/* Disable Nagle. */
		sock = 1;
		setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY,
		    &sock, sizeof(sock));
		break;
	}

	if (ai == NULL) {
		errx(EXIT_FAILURE,
		    "Unable to establish a connecting, giving up.");
	}

	if (setjmp(quit_env)) {
		goto quit;
	}

	/* handle_exitsig() is now safe. */
	(void) signal(SIGINT, handle_exitsig);

	/* Enter the command loop. */
	if (commands()) {
		quit:
		printf("Quit!\n");
	}

	printf("Thanks for visiting the land of NABU!\n");
	exit(0);
}
