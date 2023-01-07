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
 * NABU Adaptor emulation.  This handles the communication with the
 * NABU PC.
 *
 * Protocol information and message details gleaned from NabuNetworkEmulator
 * (AdaptorEmulator.cs) by Nick Daniels, so the following notice from that
 * repository is included:
 */

/*
BSD 3-Clause License

Copyright (c) 2022, Nick Daniels

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define	NABU_PROTO_INLINES

#include "adaptor.h"
#include "conn.h"
#include "image.h"
#include "log.h"
#include "retronet.h"

static const uint8_t nabu_msg_ack[] = NABU_MSGSEQ_ACK;
static const uint8_t nabu_msg_finished[] = NABU_MSGSEQ_FINISHED;

/*
 * adaptor_escape_packet --
 *	Copy the provided buffer into the connection's pktbuf,
 *	escaping any byte that's the Escape value.
 */
static void
adaptor_escape_packet(struct nabu_connection *conn, const uint8_t *buf,
    size_t len)
{
	size_t i;

	conn->pktlen = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] == NABU_MSG_ESCAPE) {
			conn->pktbuf[conn->pktlen++] = NABU_MSG_ESCAPE;
			conn->pktbuf[conn->pktlen++] = NABU_MSG_ESCAPE;
		} else {
			conn->pktbuf[conn->pktlen++] = buf[i];
		}
	}
}

/*
 * adaptor_expect_byte --
 *	Wait for an expected byte from the NABU.
 */
static bool
adaptor_expect_byte(struct nabu_connection *conn, uint8_t val)
{
	uint8_t c;

	if (! conn_recv_byte(conn, &c)) {
		log_error("[%s] Receive error.", conn->name);
		return false;
	}

	log_debug("[%s] Expected 0x%02x, got 0x%02x (%s)",
	    conn->name, val, c, val == c ? "success" : "fail");
	return val == c;
}

/*
 * adaptor_expect_sequence --
 *	Wait for a byte sequence from the NABU.
 */
static bool
adaptor_expect_sequence(struct nabu_connection *conn,
    const uint8_t *seq, size_t seqlen)
{
	size_t i;

	for (i = 0; i < seqlen; i++) {
		if (! adaptor_expect_byte(conn, seq[i])) {
			return false;
		}
	}
	return true;
}

/*
 * adaptor_expect_ack --
 *	Wait for an ACK from the NABU.
 */
static bool
adaptor_expect_ack(struct nabu_connection *conn)
{
	return adaptor_expect_sequence(conn, nabu_msg_ack,
	    sizeof(nabu_msg_ack));
}

/*
 * adaptor_send_unauthorized --
 *	Send an UNAUTHORIZED message to the NABU.
 */
static void
adaptor_send_unauthorized(struct nabu_connection *conn)
{
	log_debug("[%s] Sending UNAUTHORIZED.", conn->name);
	conn_send_byte(conn, NABU_MSG_UNAUTHORIZED);
	log_debug("[%s] Waiting for NABU to ACK.", conn->name);
	if (adaptor_expect_ack(conn)) {
		log_debug("[%s] Received ACK.", conn->name);
	} else {
		log_error("[%s] NABU failed to ACK.", conn->name);
	}
}

/*
 * adaptor_send_packet --
 *	Send a packet to the NABU.  The buffer will be freed once the
 *	packet has been sent.
 */
static void
adaptor_send_packet(struct nabu_connection *conn, uint8_t *buf, size_t len)
{
	assert(len <= NABU_MAXPACKETSIZE);

	adaptor_escape_packet(conn, buf, len);
	log_debug("[%s] Sending AUTHORIZED.", conn->name);
	conn_send_byte(conn, NABU_MSG_AUTHORIZED);
	log_debug("[%s] Waiting for NABU to ACK.", conn->name);
	if (adaptor_expect_ack(conn)) {
		log_debug("[%s] Received ACK, sending packet.",
		    conn->name);
		conn_send(conn, conn->pktbuf, conn->pktlen);
		conn_send(conn, nabu_msg_finished,
		    sizeof(nabu_msg_finished));
	} else {
		log_error("[%s] NABU failed to ACK.", conn->name);
	}
	free(buf);
}

/*
 * adaptor_send_pak --
 *	Extract the specified segment from a pre-prepared image pak
 *	and send it to the NABU.
 */
static bool
adaptor_send_pak(struct nabu_connection *conn, uint16_t segment,
    struct nabu_image *img)
{
	size_t len = NABU_TOTALPAYLOADSIZE;
	size_t off = (segment * len) + ((2 * segment) + 2);
	uint8_t *pktbuf;
	bool last = false;

	if (off >= img->length) {
		log_error(
		    "[%s] PAK %s: offset %zu exceeds pak size %zu",
		    conn->name, img->name, off, img->length);
		adaptor_send_unauthorized(conn);
		return false;
	}

	if (off + len >= img->length) {
		len = img->length - off;
		last = true;
	}

	if (len < NABU_HEADERSIZE + NABU_FOOTERSIZE) {
		log_error(
		    "[%s] PAK %s: offset %zu length %zu is nonsensical",
		    conn->name, img->name, off, len);
		adaptor_send_unauthorized(conn);
		return last;
	}

	pktbuf = malloc(len);
	if (pktbuf == NULL) {
		log_error("unable to allocate %zu byte packet buffer", len);
		adaptor_send_unauthorized(conn);
		return last;
	}

	memcpy(pktbuf, img->data + off, len);

	nabu_set_crc(&pktbuf[len - 2], nabu_crc(pktbuf, len - 2));

	log_debug("[%s] Sending segment %u of image %06X%s", conn->name,
	    segment, img->number, last ? " (last segment)" : "");

	adaptor_send_packet(conn, pktbuf, len);
	return last;
}

/*
 * adaptor_send_image --
 *	Wrap the region specified by segment in the provided image
 *	buffer in a properly structured packet and send it to the NABU.
 */
static bool
adaptor_send_image(struct nabu_connection *conn, uint16_t segment,
    struct nabu_image *img)
{
	size_t off = segment * NABU_MAXPAYLOADSIZE;
	size_t len = NABU_MAXPAYLOADSIZE;
	size_t pktlen, i;
	uint8_t *pktbuf;
	bool last = false;

	/*
	 * PAK images are pre-wrapped, so we have to process them a little
	 * differently.  Time packets don't have a channel, so check for
	 * that.
	 */
	if (img->channel != NULL && img->channel->type == IMAGE_CHANNEL_PAK) {
		return adaptor_send_pak(conn, segment, img);
	}

	if (off >= img->length) {
		log_error(
		    "image %u: segment %u offset %zu exceeds image size %zu",
		    img->number, segment, off, img->length);
		adaptor_send_unauthorized(conn);
		return false;
	}

	if (off + len >= img->length) {
		len = img->length - off;
		last = true;
	}

	pktlen = len + NABU_HEADERSIZE + NABU_FOOTERSIZE;
	pktbuf = malloc(pktlen);
	i = 0;

	if (pktbuf == NULL) {
		log_error("unable to allocate %zu byte packet buffer",
		    pktlen);
		adaptor_send_unauthorized(conn);
		return last;
	}

	/* 16 bytes of header */
	i += nabu_init_pkthdr(pktbuf, img->number, segment, off, last);

	memcpy(&pktbuf[i], img->data + off, len);	/* payload */
	i += len;

	i += nabu_set_crc(&pktbuf[i], nabu_crc(pktbuf, i));
	if (i != pktlen) {
		log_fatal("internal packet length error");
	}

	log_debug("[%s] Sending segment %u of image %06X%s", conn->name,
	    segment, img->number, last ? " (last segment)" : "");
	adaptor_send_packet(conn, pktbuf, pktlen);
	return last;
}

/*
 * adaptor_send_time --
 *	Send a time packet to the NABU.
 */
static void
adaptor_send_time(struct nabu_connection *conn)
{
	static char time_image_name[] = "TimeImage";
	struct tm tm_store, *tm;
	time_t now;
	uint8_t buf[NABU_TIMESTAMPSIZE];

	now = time(NULL);
	if (now == (time_t)-1) {
		log_error("unable to get current time: %s",
		    strerror(errno));
		memset(&tm_store, 0, sizeof(tm_store));
		tm = &tm_store;
	} else {
		tm = localtime_r(&now, &tm_store);
	}

	buf[0] = 0x02;
	buf[1] = 0x02;
	buf[2] = 0x02;
	buf[3] = 84;		/* as in 1984 */
	buf[4] = tm->tm_mon + 1;
	buf[5] = tm->tm_mday;
	buf[6] = tm->tm_hour;
	buf[7] = tm->tm_min;
	buf[8] = tm->tm_sec;

	struct nabu_image img = {
		.name = time_image_name,
		.data = buf,
		.length = sizeof(buf),
		.number = NABU_IMAGE_TIME,
	};
	adaptor_send_image(conn, 0, &img);
}

/*
 * adaptor_msg_reset --
 *	Handle the RESET message.
 */
static void
adaptor_msg_reset(struct nabu_connection *conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_ACK + NABU_MSG_CONFIRMED.",
	    conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_msg_mystery --
 *	Handle the mystery message.
 */
static void
adaptor_msg_mystery(struct nabu_connection *conn)
{
	uint8_t msg[2];

	log_debug("[%s] Sending NABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));

	log_debug("[%s] Expecting the NABU to send 2 bytes.", conn->name);
	if (! conn_recv(conn, msg, sizeof(msg))) {
		log_error("[%s] Those two bytes never arrived.", conn->name);
	} else {
		log_debug("[%s] msg[0] = 0x%02x msg[1] = 0x%02x", conn->name,
		    msg[0], msg[1]);
	}
	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_msg_channel_status --
 *	Handle the CHANNEL_STATUS message.
 */
static void
adaptor_msg_channel_status(struct nabu_connection *conn)
{
	struct image_channel *chan = conn_get_channel(conn);

	if (chan != NULL) {
		log_debug("[%s] Sending HAVE_CHANNEL.",
		    conn->name);
		conn_send_byte(conn, NABU_MSG_HAVE_CHANNEL);
		conn_send(conn, nabu_msg_finished,
		    sizeof(nabu_msg_finished));
	} else {
		log_debug("[%s] Sending NEED_CHANNEL.",
		    conn->name);
		conn_send_byte(conn, NABU_MSG_NEED_CHANNEL);
		conn_send(conn, nabu_msg_finished,
		    sizeof(nabu_msg_finished));
	}
}

/*
 * adaptor_msg_transmit_status --
 *	Handle the TRANSMIT_STATUS message.
 */
static void
adaptor_msg_transmit_status(struct nabu_connection *conn)
{
	log_debug("[%s] Sending MABU_MSGSEQ_FINISHED.", conn->name);
	conn_send(conn, nabu_msg_finished, sizeof(nabu_msg_finished));
}

/*
 * adaptor_msg_get_status --
 *	Handle the GET_STATUS message.
 */
static void
adaptor_msg_get_status(struct nabu_connection *conn)
{
	uint8_t msg;

	log_debug("[%s] Sending MABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));
	log_debug("[%s] Expecting the NABU to send status type.", conn->name);
	if (! conn_recv_byte(conn, &msg)) {
		log_error("[%s] Status type never arrived.", conn->name);
	} else {
		switch (msg) {
		case NABU_MSG_CHANNEL_STATUS:
			log_debug("[%s] Channel status requested.",
			    conn->name);
			adaptor_msg_channel_status(conn);
			break;

		case NABU_MSG_TRANSMIT_STATUS:
			log_debug("[%s] Transmit status requested.",
			    conn->name);
			adaptor_msg_transmit_status(conn);
			break;

		default:
			log_error("[%s] Unknown status type requsted: 0x%02x.",
			    conn->name, msg);
			break;
		}
	}
}

/*
 * adaptor_msg_start_up --
 *	Handle the START_UP message.
 */
static void
adaptor_msg_start_up(struct nabu_connection *conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_ACK + NABU_MSG_CONFIRMED.",
	    conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_msg_packet_request --
 *	Handle the PACKET_REQUEST message.
 */
static void
adaptor_msg_packet_request(struct nabu_connection *conn)
{
	uint8_t msg[4];

	log_debug("[%s] Sending NABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));

	if (! conn_recv(conn, msg, sizeof(msg))) {
		log_error("[%s] NABU failed to send segment/image message.",
		    conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}

	uint16_t segment = msg[0];
	uint32_t image = nabu_get_uint24(&msg[1]);
	log_debug("[%s] NABU requested segment %u of image %06X.",
	    conn->name, segment, image);

	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);

	if (image == NABU_IMAGE_TIME) {
		if (segment == 0) {
			log_debug("[%s] Sending time packet.", conn->name);
			adaptor_send_time(conn);
			return;
		}
		log_error(
		    "[%s] Unexpected request for segment %u of time image.",
		    conn->name, segment);
		adaptor_send_unauthorized(conn);
		return;
	}

	struct nabu_image *img = image_load(conn, image);
	if (img == NULL) {
		log_error("[%s] Unable to load image %06X.",
		    conn->name, image);
		adaptor_send_unauthorized(conn);
		return;
	}

	log_debug("[%s] Sending segment %u of image %06X.",
	    conn->name, segment, image);
	adaptor_send_image(conn, segment, img);
	image_release(img);
}

/*
 * adaptor_msg_change_channel --
 *	Handle the CHANGE_CHANNEL message.
 */
static void
adaptor_msg_change_channel(struct nabu_connection *conn)
{
	uint8_t msg[2];

	log_debug("[%s] Sending MABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));

	log_debug("[%s] Wating for NABU to send channel code.",
	    conn->name);
	if (! conn_recv(conn, msg, sizeof(msg))) {
		log_error("[%s] NABU failed to send channel code.",
		    conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}

	int16_t channel = (int16_t)nabu_get_uint16(msg);
	log_info("[%s] NABU selected channel 0x%04x.", conn->name, channel);

	image_channel_select(conn, channel);

	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_msg_rn_file_open --
 *	RetroNet API: File open.
 */
static void
adaptor_msg_rn_file_open(struct nabu_connection *conn)
{
	uint16_t fileFlag;
	uint8_t fileNameLen;
	uint8_t fileName[256];
	uint8_t msg[2];

	log_debug("[%s] Waiting for NABU to send fileNameLen.", conn->name);
	if (! conn_recv_byte(conn, &fileNameLen)) {
		log_error("[%s] NABU failed to send fileNameLen.",
		    conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}

	log_debug("[%s] Waiting for NABU to send fileName (%u bytes).",
	    conn->name, fileNameLen);
	if (! conn_recv(conn, fileName, fileNameLen)) {
		log_error("[%s] NABU failed to send fileName.", conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}
	fileName[fileNameLen] = '\0';

	log_debug("[%s] Waiting for NABU to send fileFlag.", conn->name);
	if (! conn_recv(conn, msg, sizeof(msg))) {
		log_error("[%s] NABU failed to send fileFlag.", conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}
	fileFlag = nabu_get_uint16(msg);

	log_debug("[%s] Waiting for NABU to send reqSlot.", conn->name);
	if (! conn_recv_byte(conn, msg)) {
		log_error("[%s] NABU failed to send reqSlot.", conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}

	log_debug("[%s] rn_api_file_open(\"%s\", 0x%04x, %u)", conn->name,
	    fileName, fileFlag, msg[0]);
	msg[0] = rn_api_file_open(conn, (const char *)fileName, fileFlag,
	    msg[0]);
	log_debug("[%s] Returning slot %u.", conn->name, msg[0]);
	conn_send_byte(conn, msg[0]);
}

/*
 * adaptor_msg_rn_fh_size --
 *	RetroNet API: File handle size.
 */
static void
adaptor_msg_rn_fh_size(struct nabu_connection *conn)
{
	uint8_t slot;
	uint8_t msg[4];
	int32_t size;

	log_debug("[%s] Waiting for NABU to send slot.", conn->name);
	if (! conn_recv_byte(conn, &slot)) {
		log_error("[%s] NABU failed to send slot.", conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}

	log_debug("[%s] rn_api_fh_size(%u)", conn->name, slot);
	size = rn_api_fh_size(conn, slot);
	log_debug("[%s] Returning size %d.", conn->name, size);
	nabu_set_uint32(msg, size);
	conn_send(conn, msg, 4);
}

/*
 * adaptor_msg_rn_fh_read --
 *	RetroNet API: File handle read.
 */
static void
adaptor_msg_rn_fh_read(struct nabu_connection *conn)
{
	uint8_t msg[7];
	uint32_t offset;
	uint16_t length;

	log_debug("[%s] Waiting for NABU to send slot, offset, length.",
	    conn->name);
	if (! conn_recv(conn, msg, sizeof(msg))) {
		log_error("[%s] NABU failed to send slot, offset, length.",
		    conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}
	offset = nabu_get_uint32(&msg[1]);
	length = nabu_get_uint16(&msg[5]);

	uint8_t *buf = malloc(length);
	if (buf == NULL) {
		log_error("[%s] Unable to allocate %zu bytes for data.",
		    conn->name, (size_t)length);
		for (unsigned int i = 0; i < length; i++) {
			conn_send_byte(conn, 0);
		}
		return;
	}
	log_debug("[%s] rn_api_fh_read(%u, %u, %u)", conn->name,
	    msg[0], offset, length);
	rn_api_fh_read(conn, msg[0], buf, offset, length);
	log_debug("[%s] Sending %u bytes of data.", conn->name, length);
	conn_send(conn, buf, length);
	free(buf);
}

/*
 * adaptor_msg_rn_fh_close --
 *	RetroNet API: File handle close.
 */
static void
adaptor_msg_rn_fh_close(struct nabu_connection *conn)
{
	uint8_t slot;

	log_debug("[%s] Waiting for NABU to send slot.", conn->name);
	if (! conn_recv_byte(conn, &slot)) {
		log_error("[%s] NABU failed to send slot.", conn->name);
		conn->state = CONN_STATE_ABORTED;
		return;
	}
	log_debug("[%s] rn_api_fh_close(%u)", conn->name, slot);
	rn_api_fh_close(conn, slot);
}

/*
 * adaptor_event_loop --
 *	Main event loop for the Adaptor emulation.
 */
void
adaptor_event_loop(struct nabu_connection *conn)
{
	uint8_t msg;

	log_info("[%s] Connection starting.", conn->name);

	for (;;) {
		/* We want to block "forever" waiting for requests. */
		conn_stop_watchdog(conn);

		log_debug("[%s] Waiting for NABU.", conn->name);
		if (! conn_recv_byte(conn, &msg)) {
			if (conn->state == CONN_STATE_EOF) {
				log_info("[%s] Peer disconnected.",
				    conn->name);
				break;
			}
			if (conn->state == CONN_STATE_CANCELLED) {
				log_info("[%s] Received cancellation request.",
				    conn->name);
				break;
			}
			if (conn->state == CONN_STATE_ABORTED) {
				log_error("[%s] Connection aborted.",
				    conn->name);
				break;
			}
			log_error("[%s] conn_recv_byte() failed, "
			    "exiting event loop.", conn->name);
			break;
		}

		/*
		 * Now that we've got a request, we don't want any given
		 * I/O to take longer than 10 seconds.
		 */
		conn_start_watchdog(conn, 10);

		switch (msg) {
		case 0:
			log_debug("[%s] Got mystery message 0x%02x.",
			    conn->name, msg);
			continue;

		default:
			log_error("[%s] Got unexpected message 0x%02x.",
			    conn->name, msg);
			continue;

		case NABU_MSG_RESET:
			log_debug("[%s] Got NABU_MSG_RESET.",
			    conn->name);
			adaptor_msg_reset(conn);
			continue;

		case NABU_MSG_MYSTERY:
			log_debug("[%s] Got NABU_MSG_MYSTERY.",
			    conn->name);
			adaptor_msg_mystery(conn);
			continue;

		case NABU_MSG_GET_STATUS:
			log_debug("[%s] Got NABU_MSG_GET_STATUS.",
			    conn->name);
			adaptor_msg_get_status(conn);
			continue;

		case NABU_MSG_START_UP:
			log_debug("[%s] Got NABU_MSG_START_UP.", conn->name);
			adaptor_msg_start_up(conn);
			continue;

		case NABU_MSG_PACKET_REQUEST:
			log_debug("[%s] Got NABU_MSG_PACKET_REQUEST.",
			    conn->name);
			adaptor_msg_packet_request(conn);
			continue;

		case NABU_MSG_CHANGE_CHANNEL:
			log_debug("[%s] Got NABU_MSG_CHANGE_CHANNEL.",
			    conn->name);
			adaptor_msg_change_channel(conn);
			continue;

		case NABU_MSG_RN_FILE_OPEN:
			log_debug("[%s] Got NABU_MSG_RN_FILE_OPEN.",
			    conn->name);
			adaptor_msg_rn_file_open(conn);
			continue;

		case NABU_MSG_RN_FH_SIZE:
			log_debug("[%s] Got NABU_MSG_RN_FH_SIZE.",
			    conn->name);
			adaptor_msg_rn_fh_size(conn);
			continue;

		case NABU_MSG_RN_FH_READ:
			log_debug("[%s] Got NABU_MSG_RN_FH_READ.",
			    conn->name);
			adaptor_msg_rn_fh_read(conn);
			continue;

		case NABU_MSG_RN_FH_CLOSE:
			log_debug("[%s] Got NABU_MSG_RN_FH_CLOSE.",
			    conn->name);
			adaptor_msg_rn_fh_close(conn);
			continue;
		}
	}
}
