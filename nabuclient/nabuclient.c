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
 * nabuclient -- a simple client of the NABU Adaptor protocol
 *
 * This exists primarily to test nabud and also to inspect replies
 * from other NABU Adaptor emulators.  This particular program is
 * really just hacked together and does the bare ninimum to enable
 * testing.  NO JUDGEMENT.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>	/* XXX HAVE_ERR_H-ize, please */
#include <limits.h>
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

#include "libnabud/cli.h"
#include "libnabud/crc16_genibus.h"
#include "libnabud/missing.h"
#include "libnabud/nabu_proto.h"
#include "libnabud/nhacp_proto.h"
#include "libnabud/retronet_proto.h"

static int	client_sock;

static const char nabuclient_version[] = VERSION;

static void
server_disconnected(void)
{
	printf("Server disconnected!\n");
	cli_quit();
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
			cli_throw();
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
			cli_throw();
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
			} else if (c == NABU_STATE_DONE) {
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
	comp_crc = crc16_genibus_fini(crc16_genibus_update(pktbuf,
	    pktidx - NABU_FOOTERSIZE, crc));
	printf("Received: %zu byte payload (R-CRC=$%04X C-CRC=$%04X -> %s).\n",
	    pktidx - NABU_FOOTERSIZE,
	    recv_crc, comp_crc, recv_crc == comp_crc ? "OK" : "BAD");
	*lenp = pktidx - NABU_FOOTERSIZE;
	return pktbuf;

 bad:
	free(pktbuf);
	cli_throw();
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

	if (*got == NABU_SERVICE_AUTHORIZED) {
		printf("AUTHORIZED!\n");
		printf("Sending NABU_MSGSEQ_ACK.\n");
		nabu_send_ack();
		return true;
	}
	if (*got == NABU_SERVICE_UNAUTHORIZED) {
		printf("*** UNAUTHORIZED! ***\n");
		printf("Sending NABU_MSGSEQ_ACK.\n");
		nabu_send_ack();
		cli_throw();
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

	printf("Expecting: NABU_STATE_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_STATE_CONFIRMED);

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
		cli_throw();
	}

	printf("Sending NABU_STATUS_SIGNAL.\n");
	nabu_send_byte(NABU_STATUS_SIGNAL);

	printf("Waiting for reply.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_reply(reply[0] == NABU_SIGNAL_STATUS_YES ||
		    reply[0] == NABU_SIGNAL_STATUS_NO);

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
		cli_throw();
	}

	printf("Sending NABU_STATUS_TRANSMIT.\n");
	nabu_send_byte(NABU_STATUS_TRANSMIT);

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

	printf("Expecting: NABU_STATE_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_STATE_CONFIRMED);

	return false;
}

static void *
send_packet_request(uint16_t segment, uint32_t image,
    struct nabu_pkthdr *pkthdr, size_t *payload_lenp)
{
	uint8_t reply[2];
	uint8_t msg[4];

	if (segment > 0xff) {
		printf("WOAH! There is only 1 byte for the segment number!\n");
		cli_throw();
	}
	if (image > 0x00FFFFFF) {
		printf("WOAH! There are only 3 bytes for the image number!\n");
		cli_throw();
	}

	printf("Sending: NABU_MSG_PACKET_REQUEST.\n");
	nabu_send_byte(NABU_MSG_PACKET_REQUEST);

	printf("Expecting: NABU_MSGSEQ_ACK.\n");
	nabu_recv(reply, sizeof(reply));
	print_reply(reply, sizeof(reply));
	check_ack(reply);

	printf("Requesting: segment %u of image %06X\n", segment, image);
	msg[0] = (uint8_t)segment;
	nabu_set_uint24(&msg[1], image);
	nabu_send(msg, sizeof(msg));

	printf("Expecting: NABU_STATE_CONFIRMED.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_byte(reply, NABU_STATE_CONFIRMED);

	printf("Expecting: authorization byte.\n");
	nabu_recv(reply, 1);
	print_reply(reply, 1);
	check_authorized(reply);

	printf("Expecing: packet header.\n");
	nabu_recv(pkthdr, sizeof(*pkthdr));
	print_pkthdr(pkthdr);

	uint16_t hdr_crc = crc16_genibus_update(pkthdr, sizeof(*pkthdr),
	    crc16_genibus_init());

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
	printf("\t day of week: $%02X\n", t->week_day);
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
	struct nabu_pkthdr pkthdr;
	size_t payload_len;
	size_t current_offset;
	uint16_t segment;
	uint32_t image;
	long val;
	void *payload;

	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	val = strtol(argv[1], NULL, 16);
	if (val < 0 || val > 0x00ffffff) {
		printf("'%s' invalid; must be between 0 - 00FFFFFF\n", argv[1]);
		cli_throw();
	}
	image = (uint32_t)val;

	for (current_offset = 0, segment = 0;; segment++) {
		payload = send_packet_request(segment, image,
		    &pkthdr, &payload_len);
		free(payload);

		/*
		 * Sanity check the packet header.
		 */
		if (nabu_get_uint24_be(pkthdr.image) != image) {
			printf("*** pkthdr.image %06X != %06X\n",
			    nabu_get_uint24_be(pkthdr.image), image);
		}
		if (pkthdr.segment_lsb != (segment & 0xff)) {
			printf("*** pkthdr.segment_lsb %u != %u\n",
			    pkthdr.segment_lsb, (segment & 0xff));
		}
#if 0
		/*
		 * These clearly have different meanings than what
		 * think they do.  Do "get-image 000001" on cycle1
		 * and look what happens to various fields at segment
		 * 16.
		 */
		if (nabu_get_uint16(pkthdr.segment) != segment) {
			printf("*** pkthdr.segment $%04X != $%04X\n",
			    nabu_get_uint16(pkthdr.segment), segment);
		}
		if (nabu_get_uint16_be(pkthdr.offset) != current_offset) {
			printf("*** pkthdr.offset %u != expected %zu\n",
			    nabu_get_uint16_be(pkthdr.offset), current_offset);
		}
#else
		(void)current_offset;
#endif
		if (pkthdr.type & 0x10) {
			printf("*** LAST PACKET!\n");
			break;
		}
		current_offset += payload_len;
	}

	return false;
}

static bool
command_change_channel(int argc, char *argv[])
{
	uint8_t msg[2];
	long channel;

	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	channel = strtol(argv[1], NULL, 10);
	if (channel < 0 || channel > 0x100) {
		printf("%s, seriously?\n", argv[1]);
		cli_throw();
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

	printf("Expecting: NABU_STATE_CONFIRMED.\n");
	nabu_recv(msg, 1);
	print_reply(msg, 1);
	check_byte(msg, NABU_STATE_CONFIRMED);

	return false;
}

static uint8_t
stext_parse_slot(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > 255) {
		printf("'%s' invalid; must be between 0 - 255\n", cp);
		cli_throw();
	}
	return (uint8_t)val;
}

static uint32_t
stext_parse_offset(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > UINT32_MAX) {
		printf("'%s' invalid offset\n", cp);
		cli_throw();
	}
	return (uint32_t)val;
}

static int32_t
stext_parse_signed_offset(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < INT32_MIN || val > INT32_MAX) {
		printf("'%s' invalid signed offset\n", cp);
		cli_throw();
	}
	return (int32_t)val;
}

static uint16_t
stext_parse_length(const char *cp, size_t maxlen)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > 0x7fff) {
		printf("'%s' invalid length\n", cp);
		cli_throw();
	}
	return (uint16_t)val;
}

static union {
	union retronet_request request;
	union retronet_reply reply;
} rn_buf;
static uint8_t *rn_cursor;

static void
rn_reset_cursor(void)
{
	rn_cursor = (uint8_t *)&rn_buf.request;
}

static size_t
rn_length(void)
{
	return (size_t)(rn_cursor - (uint8_t *)&rn_buf.request);
}

static void
rn_set_uint8(uint8_t val)
{
	*rn_cursor++ = val;
}

static void
rn_set_uint16(uint16_t val)
{
	nabu_set_uint16(rn_cursor, val);
	rn_cursor += 2;
}

static void
rn_set_uint32(uint32_t val)
{
	nabu_set_uint32(rn_cursor, val);
	rn_cursor += 4;
}

static void
rn_set_blob(void *blob, uint16_t bloblen)
{
	memcpy(rn_cursor, blob, bloblen);
	rn_cursor += bloblen;
}

static void
rn_set_filename(const char *name)
{
	size_t namelen = strlen(name);
	assert(namelen <= 255);
	rn_set_uint8((uint8_t)namelen);
	memcpy(rn_cursor, name, namelen);
	rn_cursor += namelen;
}

static void
rn_send(uint8_t op)
{
	nabu_send_byte(op);
	nabu_send(&rn_buf.request, rn_length());
}

static void
rn_recv(size_t bytes)
{
	nabu_recv(rn_cursor, bytes);
	rn_cursor += bytes;
}

static uint16_t
rn_parse_length(const char *cp)
{
	return stext_parse_length(cp, 0xffff);
}

static bool
command_rn_file_open(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t req_slot = stext_parse_slot(argv[1]);
	uint16_t flags = 0;

	if (strcmp(argv[2], "ro") == 0) {
		/* No bit to set. */
	} else if (strcmp(argv[2], "rw") == 0) {
		flags |= RN_FILE_OPEN_RW;
	} else {
		printf("What is '%s'?\n", argv[2]);
		cli_throw();
	}

	rn_set_filename(argv[3]);
	rn_set_uint16(flags);
	rn_set_uint8(req_slot);

	printf("Sending: NABU_MSG_RN_FILE_OPEN.\n");
	rn_send(NABU_MSG_RN_FILE_OPEN);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.file_open));

	printf("--> Slot %u <--\n",
	    rn_buf.reply.file_open.fileHandle);

	return false;
}

static bool
command_rn_fh_size(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);

	rn_set_uint8(slot);

	printf("Sending: NABU_MSG_RN_FH_SIZE.\n");
	rn_send(NABU_MSG_RN_FH_SIZE);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.fh_size));

	printf("--> Size %d <--\n",
	    (int32_t)nabu_get_uint32(rn_buf.reply.fh_size.fileSize));

	return false;
}

static bool
command_rn_fh_read(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = rn_parse_length(argv[3]);

	rn_set_uint8(slot);
	rn_set_uint32(offset);
	rn_set_uint16(length);

	printf("Sending: NABU_MSG_RN_FH_READ.\n");
	rn_send(NABU_MSG_RN_FH_READ);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.fh_read.returnLength));

	uint16_t retlen = nabu_get_uint16(rn_buf.reply.fh_read.returnLength);
	printf("--> Return length %u <--\n", retlen);

	if (retlen != 0) {
		rn_recv(retlen);
		printf("%*s\n", (int)retlen, rn_buf.reply.fh_read.data);
	}

	return false;
}

static bool
command_rn_fh_close(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);

	rn_set_uint8(slot);

	printf("Sending: NABU_MSG_RN_FH_CLOSE.\n");
	rn_send(NABU_MSG_RN_FH_CLOSE);

	return false;
}

static bool
command_rn_file_size(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);

	printf("Sending: NABU_MSG_RN_FILE_SIZE.\n");
	rn_send(NABU_MSG_RN_FILE_SIZE);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.file_size));

	printf("--> Size %d <--\n",
	    (int32_t)nabu_get_uint32(rn_buf.reply.file_size.fileSize));

	return false;
}

static bool
command_rn_fh_append(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint16_t length = (uint16_t)strlen(argv[2]);

	rn_set_uint8(slot);
	rn_set_uint16(length);
	rn_set_blob(argv[2], length);

	printf("Sending: NABU_MSG_RN_FH_APPEND.\n");
	rn_send(NABU_MSG_RN_FH_APPEND);

	return false;
}

static bool
command_rn_fh_insert(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = (uint16_t)strlen(argv[3]);

	rn_set_uint8(slot);
	rn_set_uint32(offset);
	rn_set_uint16(length);
	rn_set_blob(argv[3], length);

	printf("Sending: NABU_MSG_RN_FH_INSERT.\n");
	rn_send(NABU_MSG_RN_FH_INSERT);

	return false;
}

static bool
command_rn_fh_delete_range(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n"); 
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = rn_parse_length(argv[3]);

	rn_set_uint8(slot);
	rn_set_uint32(offset);
	rn_set_uint16(length);

	printf("Sending: NABU_MSG_RN_FH_DELETE_RANGE.\n");
	rn_send(NABU_MSG_RN_FH_DELETE_RANGE);

	return false;
}

static bool
command_rn_fh_replace(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = (uint16_t)strlen(argv[3]);

	rn_set_uint8(slot);
	rn_set_uint32(offset);
	rn_set_uint16(length);
	rn_set_blob(argv[3], length);

	printf("Sending: NABU_MSG_RN_FH_REPLACE.\n");
	rn_send(NABU_MSG_RN_FH_REPLACE);

	return false;
}

static bool
command_rn_file_delete(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);

	printf("Sending: NABU_MSG_RN_FILE_DELETE.\n");
	rn_send(NABU_MSG_RN_FILE_DELETE);

	return false;
}

static bool
command_rn_file_copy(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t flags = 0;

	if (argc > 3 && strcmp(argv[3], "replace") == 0) {
		flags |= RN_FILE_COPY_MOVE_REPLACE;
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);
	rn_set_filename(argv[2]);
	rn_set_uint8(flags);

	printf("Sending: NABU_MSG_RN_FILE_COPY.\n");
	rn_send(NABU_MSG_RN_FILE_COPY);

	return false;
}

static bool
command_rn_file_move(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t flags = 0;

	if (argc > 3 && strcmp(argv[3], "replace") == 0) {
		flags |= RN_FILE_COPY_MOVE_REPLACE;
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);
	rn_set_filename(argv[2]);
	rn_set_uint8(flags);

	printf("Sending: NABU_MSG_RN_FILE_MOVE.\n");
	rn_send(NABU_MSG_RN_FILE_MOVE);

	return false;
}

static void
print_rn_file_details(const struct rn_file_details *d)
{
	int namelen = d->name_length;
	uint32_t size;

	size = nabu_get_uint32(d->file_size);

	printf("--> Name length: %u <--\n", d->name_length);
	if (namelen > sizeof(d->name)) {
		namelen = sizeof(d->name);
	}
	printf("--> '%*s' <--\n", namelen, d->name);
	if (size == RN_ISDIR) {
		printf("--> DIRECTORY!\n");
	} else if (size == RN_NOENT) {
		printf("--> ENOENT!\n");
		return;
	}
	printf(" Created: %d-%d-%d %02d:%02d:%02d\n",
	    nabu_get_uint16(d->c_year), d->c_month, d->c_day,
	    d->c_hour, d->c_minute, d->c_second);
	printf("Modified: %d-%d-%d %02d:%02d:%02d\n",
	    nabu_get_uint16(d->m_year), d->m_month, d->m_day,
	    d->m_hour, d->m_minute, d->m_second);
}

static bool
command_rn_file_list(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t flags = RN_FILE_LIST_FILES | RN_FILE_LIST_DIRS;

	if (argc > 3) {
		if (strcmp(argv[3], "files") == 0) {
			flags = RN_FILE_LIST_FILES;
		} else if (strcmp(argv[3], "dirs") == 0) {
			flags = RN_FILE_LIST_DIRS;
		}
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);
	rn_set_filename(argv[2]);
	rn_set_uint8(flags);

	printf("Sending: NABU_MSG_RN_FILE_LIST.\n");
	rn_send(NABU_MSG_RN_FILE_LIST);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.file_list));

	unsigned int matches =
	    nabu_get_uint16(rn_buf.reply.file_list.matchCount);

	printf("--> %u matches <--\n", matches);

	if (matches == 0) {
		return false;
	}

	for (unsigned int i = 0; i < matches; i++) {
		rn_reset_cursor();
		rn_set_uint16((uint16_t)i);
		rn_send(NABU_MSG_RN_FILE_LIST_ITEM);
		rn_reset_cursor();
		rn_recv(sizeof(rn_buf.reply.file_list_item));
		print_rn_file_details(&rn_buf.reply.file_list_item);
	}

	return false;
}

static bool
command_rn_file_details(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	rn_set_filename(argv[1]);

	printf("Sending: NABU_MSG_RN_FILE_DETAILS.\n");
	rn_send(NABU_MSG_RN_FILE_DETAILS);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.file_details));

	print_rn_file_details(&rn_buf.reply.file_details);

	return false;
}

static bool
command_rn_fh_details(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);

	rn_set_uint8(slot);

	printf("Sending: NABU_MSG_RN_FH_DETAILS.\n");
	rn_send(NABU_MSG_RN_FH_DETAILS);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.fh_details));

	print_rn_file_details(&rn_buf.reply.fh_details);

	return false;
}

static bool
command_rn_fh_readseq(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	uint16_t length = rn_parse_length(argv[2]);

	rn_set_uint8(slot);
	rn_set_uint16(length);

	printf("Sending: NABU_MSG_RN_FH_READSEQ.\n");
	rn_send(NABU_MSG_RN_FH_READSEQ);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.fh_readseq.returnLength));

	uint16_t retlen = nabu_get_uint16(rn_buf.reply.fh_readseq.returnLength);
	printf("--> Return length %u <--\n", retlen);

	if (retlen != 0) {
		rn_recv(retlen);
		printf("%*s\n", (int)retlen, rn_buf.reply.fh_readseq.data);
	}

	return false;
}

static bool
command_rn_fh_seek(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	rn_reset_cursor();

	uint8_t slot = stext_parse_slot(argv[1]);
	int32_t offset = stext_parse_signed_offset(argv[2]);
	uint8_t whence;

	if (strcmp(argv[3], "set") == 0) {
		whence = RN_SEEK_SET;
	} else if (strcmp(argv[3], "cur") == 0) {
		whence = RN_SEEK_CUR;
	} else if (strcmp(argv[3], "end") == 0) {
		whence = RN_SEEK_END;
	} else {
		printf("lol, wut?\n");
		cli_throw();
	}

	rn_set_uint8(slot);
	rn_set_uint32((uint32_t)offset);
	rn_set_uint8(whence);

	printf("Sending: NABU_MSG_RN_FH_SEEK.\n");
	rn_send(NABU_MSG_RN_FH_SEEK);

	rn_reset_cursor();
	rn_recv(sizeof(rn_buf.reply.fh_seek));

	printf("--> New offset: %u <--\n",
	    nabu_get_uint32(rn_buf.reply.fh_seek.offset));

	return false;
}

static union {
	struct nabu_msg_start_nhacp start;
	struct nhacp_request request;
	struct nhacp_response reply;
} nhacp_buf;
static uint16_t nhacp_length;
static uint16_t nhacp_version;

static void
nhacp_send(uint8_t op, uint16_t length)
{
	nhacp_buf.request.generic.type = op;
	nabu_set_uint16(nhacp_buf.request.length, length);
	nabu_send(&nhacp_buf.request,
	    length + sizeof(nhacp_buf.request.length));
}

static void
nhacp_recv(void)
{
	nabu_recv(nhacp_buf.reply.length, sizeof(nhacp_buf.reply.length));
	uint16_t length = nabu_get_uint16(nhacp_buf.reply.length);

	printf("NHACP response length: 0x%04x\n", length);
	if (length == 0 || length > NHACP_MAX_MESSAGELEN) {
		printf("The server is drunk.\n");
		cli_throw();
	}
	nabu_recv(&nhacp_buf.reply.generic, length);
	nhacp_length = length;
}

static void
nhacp_decode_date_time(const char *label, const struct nhacp_date_time *dt)
{
	if (isascii(dt->yyyymmdd[0]) &&
	    isascii(dt->yyyymmdd[1]) &&
	    isascii(dt->yyyymmdd[2]) &&
	    isascii(dt->yyyymmdd[3]) &&
	    isascii(dt->yyyymmdd[4]) &&
	    isascii(dt->yyyymmdd[5]) &&
	    isascii(dt->yyyymmdd[6]) &&
	    isascii(dt->yyyymmdd[7]) &&
	    isascii(dt->hhmmss[0]) &&
	    isascii(dt->hhmmss[1]) &&
	    isascii(dt->hhmmss[2]) &&
	    isascii(dt->hhmmss[3]) &&
	    isascii(dt->hhmmss[4]) &&
	    isascii(dt->hhmmss[5])) {
		printf("--> %s %c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c <--\n", label,
		    dt->yyyymmdd[0],
		    dt->yyyymmdd[1],
		    dt->yyyymmdd[2],
		    dt->yyyymmdd[3],
		    dt->yyyymmdd[4],
		    dt->yyyymmdd[5],
		    dt->yyyymmdd[6],
		    dt->yyyymmdd[7],
		    dt->hhmmss[0],
		    dt->hhmmss[1],
		    dt->hhmmss[2],
		    dt->hhmmss[3],
		    dt->hhmmss[4],
		    dt->hhmmss[5]);
	} else {
		printf("--> BAD %s DATA <--\n", label);
	}
}

static void
nhacp_decode_file_attrs(const struct nhacp_file_attrs *attrs)
{
	uint32_t file_size = nabu_get_uint32(attrs->file_size);
	uint16_t flags = nabu_get_uint16(attrs->flags);

	printf("--> Flags: 0x%04x%s%s%s%s\n",
	    flags,
	    (flags & NHACP_AF_RD)   ? " RD"   : "",
	    (flags & NHACP_AF_WR)   ? " WR"   : "",
	    (flags & NHACP_AF_DIR)  ? " DIR"  : "",
	    (flags & NHACP_AF_SPEC) ? " SPEC" : "");
	printf("--> Size: %u\n", file_size);
	nhacp_decode_date_time("Modified:", &attrs->mtime);
}

static void
nhacp_decode_reply(void)
{
	uint16_t length;

	nhacp_recv();

	switch (nhacp_buf.reply.generic.type) {
	case NHACP_RESP_NHACP_STARTED:
		if (nhacp_length < sizeof(nhacp_buf.reply.nhacp_started)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		nhacp_buf.reply.nhacp_started.adapter_id[
		    nhacp_buf.reply.nhacp_started.adapter_id_length] = '\0';
		printf("Got: NHACP_RESP_NHACP_STARTED.\n");
		printf("Server Vers=$%02X $%02X ID len=%u '%s'\n",
		    nhacp_buf.reply.nhacp_started.version[0],
		    nhacp_buf.reply.nhacp_started.version[1],
		    nhacp_buf.reply.nhacp_started.adapter_id_length,
		    nhacp_buf.reply.nhacp_started.adapter_id);
		break;

	case NHACP_RESP_OK:
		printf("Got: NHACP_RESP_OK.\n");
		break;

	case NHACP_RESP_ERROR:
		printf("Got: NHACP_RESP_ERROR.\n");
		if (nhacp_length < sizeof(nhacp_buf.reply.error)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		if (nhacp_buf.reply.error.message_length != 0) {
			nhacp_buf.reply.error.message[
			    nhacp_buf.reply.error.message_length] = '\0';
			printf("--> Code %u Message '%s' <--\n",
			    nabu_get_uint16(nhacp_buf.reply.error.code),
			    (char *)nhacp_buf.reply.error.message);
		} else {
			printf("--> Code %u <--\n",
			    nabu_get_uint16(nhacp_buf.reply.error.code));
		}
		break;

	case NHACP_RESP_STORAGE_LOADED:
		printf("Got: NHACP_RESP_STORAGE_LOADED.\n");
		if (nhacp_length < sizeof(nhacp_buf.reply.storage_loaded)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		printf("--> Slot %u Size %u <--\n",
		    nhacp_buf.reply.storage_loaded.slot,
		    nabu_get_uint32(nhacp_buf.reply.storage_loaded.length));
		break;

	case NHACP_RESP_DATA_BUFFER:
		printf("Got: NHACP_RESP_DATA_BUFFER.\n");
		if (nhacp_length < sizeof(nhacp_buf.reply.data_buffer)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		length = nabu_get_uint16(nhacp_buf.reply.data_buffer.length);
		printf("--> Length: %u <--\n", length);
		printf("--> START\n");
		printf("%-*s\n", length,
		    (char *)nhacp_buf.reply.data_buffer.data);
		printf("<-- END\n");
		break;

	case NHACP_RESP_DATE_TIME:
		printf("Got: NHACP_RESP_DATE_TIME.\n");
		if (nhacp_length < sizeof(nhacp_buf.reply.date_time)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		print_reply(&nhacp_buf.reply.date_time.date_time,
		    sizeof(nhacp_buf.reply.date_time.date_time));
		nhacp_decode_date_time("DATE-TIME",
		    &nhacp_buf.reply.date_time.date_time);
		break;

	case NHACP_RESP_DIR_ENTRY:
		printf("Got: NHACP_RESP_DIR_ENTRY.\n");
		if (nhacp_length < sizeof(nhacp_buf.reply.dir_entry)) {
			printf("*** RUNT ***\n");
			cli_throw();
		}
		nhacp_buf.reply.dir_entry.name[
		    nhacp_buf.reply.dir_entry.name_length] = '\0';
		printf("--> File name: '%s' <--\n",
		    (char *)nhacp_buf.reply.dir_entry.name);
		nhacp_decode_file_attrs(&nhacp_buf.reply.dir_entry.attrs);
		break;

	default:
		printf("Got: unknown response type 0x%02x\n",
		    nhacp_buf.reply.generic.type);
		break;
	}
}

static uint16_t
nhacp_parse_length(const char *cp)
{
	return stext_parse_length(cp, 0x7fff);
}

static uint16_t
nhacp_parse_error_code(const char *cp)
{
	long val = strtol(cp, NULL, 0);
	if (val < 0 || val > UINT16_MAX) {
		printf("'%s' invalid error code\n", cp);
		cli_throw();
	}
	return (uint16_t)val;
}

static bool
command_nhacp_start_0_0(int argc, char *argv[])
{
	nhacp_version = NHACP_VERS_0_0;

	printf("Sending: NABU_MSG_START_NHACP_0_0.\n");
	nabu_send_byte(NABU_MSG_START_NHACP_0_0);

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_start(int argc, char *argv[])
{
	nhacp_buf.start.type = NABU_MSG_START_NHACP;
	nhacp_buf.start.magic[0] = 'A';
	nhacp_buf.start.magic[1] = 'C';
	nhacp_buf.start.magic[2] = 'P';
	nabu_set_uint16(nhacp_buf.start.version,
	    (nhacp_version = NHACP_VERS_0_1));

	printf("Sending: NABU_MSG_START_NHACP.\n");
	nabu_send(&nhacp_buf.start, sizeof(nhacp_buf.start));

	nhacp_decode_reply();
	return false;

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_get_date_time(int argc, char *argv[])
{
	printf("Sending: NHACP_REQ_GET_DATE_TIME.\n");
	nhacp_send(NHACP_REQ_GET_DATE_TIME, 1);

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_open(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t req_slot = stext_parse_slot(argv[1]);

	nhacp_buf.request.storage_open.req_slot = req_slot;
	nhacp_buf.request.storage_open.url_length = (uint8_t)strlen(argv[2]);
	strcpy((char *)nhacp_buf.request.storage_open.url_string, argv[2]);

	bool have_accmode = false;
	uint16_t oflags = 0;
	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "rw") == 0 ||
		    strcmp(argv[i], "rdwr") == 0) {
			if (have_accmode) {
				printf("Already have access mode.\n");
				cli_throw();
			}
			have_accmode = true;
			oflags |= NHACP_O_RDWR;
			continue;
		}
		if (strcmp(argv[i], "ro") == 0 ||
		    strcmp(argv[i], "rdonly") == 0) {
			if (have_accmode) {
				printf("Already have access mode.\n");
				cli_throw();
			}
			have_accmode = true;
			oflags |= NHACP_O_RDONLY;
			continue;
		}
		if (strcmp(argv[i], "creat") == 0 ||
		    strcmp(argv[i], "create") == 0) {
			oflags |= NHACP_O_CREAT;
			continue;
		}
		if (strcmp(argv[i], "excl") == 0) {
			oflags |= NHACP_O_EXCL;
			continue;
		}
		if (strcmp(argv[i], "dir") == 0) {
			oflags |= NHACP_O_DIRECTORY;
			continue;
		}
		printf("Unknown open flag: %s\n", argv[i]);
		cli_throw();
	}
	nabu_set_uint16(nhacp_buf.request.storage_open.flags, oflags);

	printf("Sending: NHACP_REQ_STORAGE_OPEN.\n");
	nhacp_send(NHACP_REQ_STORAGE_OPEN,
	    sizeof(nhacp_buf.request.storage_open) + strlen(argv[2]));

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_get(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = nhacp_parse_length(argv[3]);

	nhacp_buf.request.storage_get.slot = slot;
	nabu_set_uint32(nhacp_buf.request.storage_get.offset, offset);
	nabu_set_uint16(nhacp_buf.request.storage_get.length, length);

	printf("Sending: NHACP_REQ_STORAGE_GET.\n");
	nhacp_send(NHACP_REQ_STORAGE_GET,
	    sizeof(nhacp_buf.request.storage_get));

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_get_block(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t blkno = stext_parse_offset(argv[2]);
	uint16_t blklen = nhacp_parse_length(argv[3]);

	nhacp_buf.request.storage_get_block.slot = slot;
	nabu_set_uint32(nhacp_buf.request.storage_get_block.block_number,
	    blkno);
	nabu_set_uint16(nhacp_buf.request.storage_get_block.block_length,
	    blklen);

	printf("Sending: NHACP_REQ_STORAGE_GET_BLOCK.\n");
	nhacp_send(NHACP_REQ_STORAGE_GET_BLOCK,
	    sizeof(nhacp_buf.request.storage_get_block));

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_put(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t offset = stext_parse_offset(argv[2]);
	uint16_t length = strlen(argv[3]);

	nhacp_buf.request.storage_put.slot = slot;
	nabu_set_uint32(nhacp_buf.request.storage_put.offset, offset);
	nabu_set_uint16(nhacp_buf.request.storage_put.length, length);
	memcpy(nhacp_buf.request.storage_put.data, argv[3], length);

	printf("Sending: NHACP_REQ_STORAGE_PUT.\n");
	nhacp_send(NHACP_REQ_STORAGE_PUT,
	    sizeof(nhacp_buf.request.storage_put) + length);

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_put_block(int argc, char *argv[])
{
	if (argc < 5) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);
	uint32_t blkno = stext_parse_offset(argv[2]);
	uint16_t blklen = nhacp_parse_length(argv[3]);
	uint8_t val = stext_parse_slot(argv[4]);	/* good enough */

	nhacp_buf.request.storage_put_block.slot = slot;
	nabu_set_uint32(nhacp_buf.request.storage_put_block.block_number,
	    blkno);
	nabu_set_uint16(nhacp_buf.request.storage_put_block.block_length,
	    blklen);
	memset(nhacp_buf.request.storage_put_block.data, val, blklen);

	printf("Sending: NHACP_REQ_STORAGE_PUT_BLOCK.\n");
	nhacp_send(NHACP_REQ_STORAGE_PUT_BLOCK,
	    sizeof(nhacp_buf.request.storage_put_block) + blklen);

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_storage_close(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);

	nhacp_buf.request.file_close.slot = slot;

	printf("Sending: NHACP_REQ_FILE_CLOSE.\n");
	nhacp_send(NHACP_REQ_FILE_CLOSE,
	    sizeof(nhacp_buf.request.file_close));

	/* There is no reply to this request. */

	return false;
}

static bool
command_nhacp_get_error_details(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint16_t code = nhacp_parse_error_code(argv[1]);

	nabu_set_uint16(nhacp_buf.request.get_error_details.code, code);
	nhacp_buf.request.get_error_details.max_message_len = 255;

	printf("Sending: NHACP_REQ_GET_ERROR_DETAILS.\n");
	nhacp_send(NHACP_REQ_GET_ERROR_DETAILS,
	    sizeof(nhacp_buf.request.get_error_details));

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_list_dir(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);
	const char *pattern = argv[2];

	nhacp_buf.request.list_dir.slot = slot;
	nhacp_buf.request.list_dir.pattern_length = (uint8_t)strlen(pattern);
	memcpy(nhacp_buf.request.list_dir.pattern, pattern,
	    nhacp_buf.request.list_dir.pattern_length);

	printf("Sending: NHACP_REQ_LIST_DIR.\n");
	nhacp_send(NHACP_REQ_LIST_DIR,
	    sizeof(nhacp_buf.request.list_dir) +
	    nhacp_buf.request.list_dir.pattern_length);

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_get_dir_entry(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Args, bro.\n");
		cli_throw();
	}

	uint8_t slot = stext_parse_slot(argv[1]);

	nhacp_buf.request.get_dir_entry.slot = slot;
	nhacp_buf.request.get_dir_entry.max_name_length = 255;

	printf("Sending: NHACP_REQ_GET_DIR_ENTRY.\n");
	nhacp_send(NHACP_REQ_GET_DIR_ENTRY,
	    sizeof(nhacp_buf.request.get_dir_entry));

	nhacp_decode_reply();
	return false;
}

static bool
command_nhacp_end_protocol(int argc, char *argv[])
{
	printf("Sending: NHACP_REQ_END_PROTOCOL.\n");
	nhacp_send(NHACP_REQ_END_PROTOCOL, 1);

	return false;
}

static bool	command_help(int, char *[]);

static const struct cmdtab cmdtab[] = {
	{ .name = "exit",		.func = command_exit },
	{ .name = "quit",		.func = command_exit },

	{ .name = "help",		.func = command_help },
	{ .name = "?",			.func = command_help },

	{ .name = "reset",		.func = command_reset },
	{ .name = "start-up",		.func = command_start_up },
	{ .name = "change-channel",	.func = command_change_channel },
	{ .name = "get-channel-status",	.func = command_get_channel_status },
	{ .name = "get-transmit-status",.func = command_get_transmit_status },
	{ .name = "get-time",		.func = command_get_time },
	{ .name = "get-image",		.func = command_get_image },

	{ .name = "rn-file-open",	.func = command_rn_file_open },
	{ .name = "rn-fh-size",		.func = command_rn_fh_size },
	{ .name = "rn-fh-read",		.func = command_rn_fh_read },
	{ .name = "rn-fh-close",	.func = command_rn_fh_close },
	{ .name = "rn-file-size",	.func = command_rn_file_size },
	{ .name = "rn-fh-append",	.func = command_rn_fh_append },
	{ .name = "rn-fh-insert",	.func = command_rn_fh_insert },
	{ .name = "rn-fh-delete-range",	.func = command_rn_fh_delete_range },
	{ .name = "rn-fh-replace",	.func = command_rn_fh_replace },
	{ .name = "rn-file-delete",	.func = command_rn_file_delete },
	{ .name = "rn-file-copy",	.func = command_rn_file_copy },
	{ .name = "rn-file-move",	.func = command_rn_file_move },
	{ .name = "rn-file-list",	.func = command_rn_file_list },
	{ .name = "rn-file-details",	.func = command_rn_file_details },
	{ .name = "rn-fh-details",	.func = command_rn_fh_details },
	{ .name = "rn-fh-readseq",	.func = command_rn_fh_readseq },
	{ .name = "rn-fh-seek",		.func = command_rn_fh_seek },

	{ .name = "nhacp-start-0-0",	.func = command_nhacp_start_0_0 },
	{ .name = "nhacp-start",	.func = command_nhacp_start },
	{ .name = "nhacp-storage-open",	.func = command_nhacp_storage_open },
	{ .name = "nhacp-storage-get",	.func = command_nhacp_storage_get },
	{ .name = "nhacp-storage-put",	.func = command_nhacp_storage_put },
	{ .name = "nhacp-storage-get-block",
				.func = command_nhacp_storage_get_block },
	{ .name = "nhacp-storage-put-block",
				.func = command_nhacp_storage_put_block },
	{ .name = "nhacp-get-date-time", .func = command_nhacp_get_date_time },
	{ .name = "nhacp-storage-close", .func = command_nhacp_storage_close },
	{ .name = "nhacp-get-error-details",
				.func = command_nhacp_get_error_details },
	{ .name = "nhacp-list-dir",	.func = command_nhacp_list_dir },
	{ .name = "nhacp-get-dir-entry",.func = command_nhacp_get_dir_entry },
	{ .name = "nhacp-end-protocol",	.func = command_nhacp_end_protocol },

	CMDTAB_EOL(cli_command_unknown)
};

static bool
command_help(int argc, char *argv[])
{
	return cli_help(cmdtab);
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

	/* Enter the command loop. */
	cli_commands(getprogname(), cmdtab, NULL, NULL);

	printf("Thanks for visiting the land of NABU!\n");
	exit(0);
}
