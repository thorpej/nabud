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

/*
 * NABU Adaptor emulation.  This handles the communication with the
 * NABU PC.
 *
 * Protocol information and message details gleaned from NabuNetworkEmulator
 * (AdaptorEmulator.cs) by Nick Daniels.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "conn.h"

static const uint8_t nabu_msg_request_channel_code[] =
    NABU_MSGSEQ_REQUEST_CHANNEL_CODE;
static const uint8_t nabu_msg_confirm_channel_code[] =
    NABU_MSGSEQ_CONFIRM_CHANNEL_CODE;
static const uint8_t nabu_msg_ack = NABU_MSGSEQ_ACK;
static const uint8_t nabu_msg_initialized = NABU_MSGSEQ_INITIALIZED;
static const uint8_t nabu_msg_end = NABU_MSGSEQ_END;

/*
 * adaptor_get_int16 --
 *	Get a 16-bit integer from the specified buffer.
 */
static uint16_t
adaptor_get_int16(const uint8_t *buf)
{
	/* little-endian */
	return buf[0] | (buf[1] << 8);
}

/*
 * adaptor_get_int24 --
 *	Get a 24-bit integer from the specified buffer.
 */
static uint32_t
adaptor_get_int24(const uint8_t *buf)
{
	/* little-endian */
	return buf[0] | (buf[1] << 8) | (buf[2] << 16);
}

/*
 * adaptor_crc --
 *	Compute the CRC of the provided data buffer.
 */
static uint16_t
adaptor_crc(const uint8_t *buf, size_t len)
{
	static const uint16_t crctab[] = NABU_CRC_TAB;
	size_t i;
	uint16_t crc = 0xffff;
	uint8_t c;

	for (i = 0; i < len; i++) {
		c = (crc >> 8) ^ buf[i];
		crc <<= 8;
		crc ^= crctab[c];
	}
	return crc;
}

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
 * adaptor_send_abort --
 *	Send an "abort" to the NABU.
 */
static void
adaptor_send_abort(struct nabu_connection *conn)
{
	conn_send_byte(conn, NABU_MSG_UNAUTHORIZED);
}

/*
 * adaptor_msg_to_string --
 *	This is just a silly little helper function so I can log
 *	a decent message in adaptor_expect().
 */
static char *
adaptor_msg_to_string(const uint8_t *msg, size_t msglen)
{
	char *cp0, *cp;
	size_t i;

	cp0 = cp = malloc(msglen * 5);
	assert(cp0 != NULL);		/* &shrug; */

	for (i = 0; i < msglen; i++) {
		cp += sprintf(cp, "0x%02x%s", msg[i],
		    i == msglen - 1 ? "" : " ");
	}
	return cp0;
}

/*
 * adaptor_expect --
 *	Wait for an expected message from the NABU.
 */
static bool
adaptor_expect(struct nabu_connection *conn, const uint8_t *msg, size_t msglen)
{
	uint8_t buf[8];		/* We expect these to be small. */
	ssize_t actual;

	assert(msglen <= sizeof(buf));

	actual = conn_recv(conn, buf, msglen);
	if (actual <= 0) {
		log_error("[%s] Receive error.", conn->name);
		return false;
	}

	if (memcmp(msg, buf, msglen) == 0) {
		/* Got expected message! */
		return true;
	}

	/*
	 * Log what we got vs what we expected.
	 */
	char *expected = adaptor_msg_to_string(msg, msglen);
	char *received = adaptor_msg_to_string(buf, msglen);
	log_error("[%s] Expected %s, received %s", conn->name,
	    expected, received);
	free(expected);
	free(received);
}

/*
 * adaptor_send_packet --
 *	Send a packet to the NABU.  The buffer will be freed once the
 *	packet has been sent.
 */
static void
adaptor_send_packet(struct nabu_connection *conn, uint8_t *buf, size_t len)
{
	if (len > NABU_MAXPACKETSIZE) {
		log_error("packet length %zu exceeds NABU_MAXPACKETSIZE (%d)",
		    len, NABU_MAXPACKETSIZE);
		adaptor_send_abort(conn);
	} else {
		adaptor_escape_packet(conn, buf, len);
		conn_send_byte(conn, NABU_MSG_AUTHORIZED);
		if (adaptor_expect(conn, nabu_msg_ack, sizeof(nabu_msg_ack))) {
			conn_send(conn, conn->pktbuf, conn->pktlen);
			conn_send(conn, nabu_msg_end, sizeof(nabu_msg_end));
		} else {
			log_error("[%s] Protocol error.", conn->name);
		}
	}
	free(buf);
}

/*
 * adaptor_send_pak --
 *	Extract the specified packet from a pre-prepared segment pak
 *	and send it to the NABU.
 */
static void
adaptor_send_pak(struct nabu_connection *conn, uint16_t packet,
    const struct nabu_segment *seg)
{
	size_t len = NABU_TOTALPAYLOADSIZE;
	size_t off = (packet * len) + ((2 * packet) + 2);
	uint8_t *pktbuf;

	if (off >= seg->length) {
		log_error(
		    "[%s] PAK %s: offset %zu exceeds pak size %zu",
		    conn->name, seg->name, off, seg->length);
		adaptor_send_abort(conn);
		return;
	}

	if (off + len >= pak->length) {
		len = seg->length - offset;
	}

	if (len < NABU_HEADERSIZE + NABU_FOOTERSIZE) {
		log_error(
		    "[%s] PAK %s: offset %zu length %zu is nonsensical",
		    conn->naname, seg->name, off, len);
		adaptor_send_abort(conn);
		return;
	}

	pktbuf = malloc(len);
	if (pktbuf == NULL) {
		log_error("unable to allocate %zu byte packet buffer", len);
		adaptor_send_abort(conn);
		return;
	}

	memcpy(pktbuf, seg->data + off, len);

	uint16_t crc = adaptor_crc(pktbuf, len - 2);
	pktbuf[len - 2] = (uint8_t)(crc >> 8) ^ 0xff;	/* CRC MSB */
	pktbuf[len - 1] = (uint8_t)(crc)      ^ 0xff;	/* CRC LSB */

	adaptor_send_packet(pktbuf, pktlen);
}

/*
 * adaptor_send_segment --
 *	Wrap the region specified by packet in the provided segment
 *	buffer in a properly structured packet and send it to the NABU.
 */
static void
adaptor_send_segment(struct nabu_connection *conn, uint16_t packet,
    const struct nabu_segment *seg)
{
	size_t off = packet * NABU_MAXPAYLOADSIZE;
	size_t len = NABU_MAXPAYLOADSIZE;
	size_t pktlen, i;
	uint8_t *pktbuf;
	bool last = false;

	/*
	 * PAK segments are pre-wrapped, so we have to process them a little
	 * differently.
	 */
	if (seg->is_pak) {
		adaptor_send_pak(conn, packet, seg);
		return;
	}

	if (off >= seg->length) {
		log_error(
		    "segment %u: packet %u offset %zu exceeds segment size %zu",
		    seg->segment, packet, offset, seg->length);
		adaptor_send_abort(conn);
		return;
	}

	if (off + len >= seg->length) {
		len = seg->length - off;
		last = true;
	}

	pktlen = len + NABU_HEADERSIZE + NABU_FOOTERSIZE;
	pktbuf = malloc(pktlen);
	i = 0;

	if (pktbuf == NULL) {
		log_error("unable to allocate %zu byte packet buffer",
		    pktlen);
		adaptor_send_abort(conn);
		return;
	}

	/* 16 bytes of header */
	pktbuf[i++] = (uint8_t)(segment >> 16);		/* segment MSB */
	pktbuf[i++] = (uint8_t)(segment >> 8);
	pktbuf[i++] = (uint8_t)(segment);		/* segment LSB */
	pktbuf[i++] = (uint8_t)(packet);		/* packet LSB */
	pktbuf[i++] = 0x01;				/* owner */
	pktbuf[i++] = 0x7f;				/* tier MSB */
	pktbuf[i++] = 0xff;
	pktbuf[i++] = 0xff;
	pktbuf[i++] = 0xff;				/* tier LSB */
	pktbuf[i++] = 0x7f;				/* mystery byte */
	pktbuf[i++] = 0x80;				/* mystery byte */
	pktbuf[i++] = (packet == 0 ? 0xa1 : 0x20) |	/* packet type */
	              (last        ? 0x10 : 0x00)	/* end of segment */
	pktbuf[i++] = (uint8_t)(packet);		/* packet LSB */
	pktbuf[i++] = (uint8_t)(packet >> 8);		/* packet MSB */
	pktbuf[i++] = (uint8_t)(offset >> 8);		/* offset MSB */
	pktbuf[i++] = (uint8_t)(offset);		/* offset LSB */

	memcpy(&pktbuf[i], seg->data + off, len);	/* payload */
	i += len;

	uint16_t crc = adaptor_crc(pktbuf, i);
	pktbuf[i++] = (uint8_t)(crc >> 8) ^ 0xff;	/* CRC MSB */
	pktbuf[i++] = (uint8_t)(crc)      ^ 0xff;	/* CRC LSB */
	if (i != pktlen) {
		log_fatal("internal packet length error");
	}

	adaptor_send_packet(pktbuf, pktlen);
}

/*
 * adaptor_send_time --
 *	Send a time packet to the NABU.
 */
static void
adaptor_send_time(struct nabu_connection *conn)
{
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
	buf[3] = 0x54;		/* 1984 */
	buf[4] = tm->tm_mon + 1;
	buf[5] = tm->tm_mday;
	buf[6] = tm->tm_hour;
	buf[7] = tm->tm_min;
	buf[8] = tm->tm_sec;

	struct nabu_segment seg = {
		.name = "TimeSegment",
		.data = buf,
		.length = sizeof(buf),
		.segment = NABU_SEGMENT_TIME,
		.is_pak = false,
	};
	adaptor_send_segment(conn, 0, &seg);
}

/*
 * adaptor_msg_channel_status --
 *	Handle the CHANNEL_STATUS message.
 */
static void
adaptor_msg_channel_status(conn)
{
	if (conn->channel_valid) {
		log_info("[%s] Confirm channel code: 0x%04x.",
		    conn->name, conn->channel);
		conn_send(conn, nabu_msg_confirm_channel_code,
		    sizeof(nabu_msg_confirm_channel_code));
	} else {
		log_info("[%s] Requesting channel code.", conn->name);
		conn_send(conn, nabu_msg_request_channel_code,
		    sizeof(nabu_msg_request_channel_code));
	}
}

/*
 * adaptor_msg_ready --
 *	Handle the READY message.
 */
static void
adaptor_msg_ready(conn)
{
	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_msg_1e --
 *	Handle the slightly mysterious 0x1e message.
 */
static void
adaptor_msg_1e(conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_END.", conn->name);
	conn_send(conn, nabu_msg_end, sizeof(nabu_msg_end));
}

/*
 * adaptor_msg_wait --
 *	Handle the WAIT message.
 */
static void
adaptor_msg_wait(conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));
}

/*
 * adaptor_msg_starting_up --
 *	Handle the STARTING_UP message.
 */
static void
adaptor_msg_starting_up(conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));
}

/*
 * adaptor_msg_initialize --
 *	Handle the INITIALIZE message.
 */
static void
adaptor_msg_initialize(conn)
{
	log_debug("[%s] Sending NABU_MSGSEQ_INITIALIZED.", conn->name);
	conn_send(conn, nabu_msg_initialized, sizeof(nabu_msg_initialized));
}

/*
 * adaptor_msg_packet_request --
 *	Handle the PACKET_REQUEST message.
 */
static void
adaptor_msg_packet_request(conn)
{
	static const unsigned int recv_timo = 5;
	uint8_t msg[4];
	ssize_t msglen;

	log_debug("[%s] Sending NABU_MSGSEQ_ACK.", conn->name);
	conn_send(conn, nabu_msg_ack, sizeof(nabu_msg_ack));

	msglen = conn_recv(conn, msg, sizeof(msg));
	if (msglen != sizeof(msg)) {
		log_error("[%s] NABU failed to send packet/segment message.",
		    conn->name);
		conn->aborted = true;
		return;
	}

	uint16_t packet = msg[0];
	uint32_t segment = adaptor_get_int24(&msg[1]);
	log_debug("[%s] NABU requested packet %u of segment 0x%08x.",
	    conn->name, packet, segment);

	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);

	if (segment == NABU_SEGMENT_TIME) {
		if (packet == 0) {
			log_debug("[%s] Sending time packet.", conn->name);
			adaptor_send_time(conn);
			return;
		}
		log_error(
		    "[%s] Unexpected request for packet %u of time segment.",
		    conn->name, packet);
		adaptor_send_abort(conn);
		return;
	}

	const struct nabu_segment *seg = segment_load(conn, segment);
	if (seg == NULL) {
		log_error("[%s] Unable to load segment 0x%08x.",
		    conn->name, segment);
		adaptor_send_abort(conn);
		return;
	}

	log_debug("[%s] Sending packet %u of %ssegment 0x%08x.",
	    conn->name, packet, segment);
	adaptor_send_segment(conn, packet, seg->is_pak ? "PAK " : "", seg);
}

/*
 * adaptor_msg_change_channel --
 *	Handle the CHANGE_CHANNEL message.
 */
static void
adaptor_msg_change_channel(conn)
{
	static const unsigned int recv_timo = 5;
	uint8_t msg[2];
	ssize_t msglen;

	msglen = conn_recv(conn, msg, sizeof(msg));
	if (msglen != sizeof(msg)) {
		log_error("[%s] NABU failed to send channel code.",
		    conn->name);
		conn->aborted = true;
		return;
	}

	uint16_t channel = adaptor_get_int16(msg);
	log_info("[%s] NABU selected channel 0x%04x.", conn->name, channel);

	if (channel < 0x100) {
		conn->channel = channel;
		conn->channel_valid = true;
	} else {
		conn->channel = 0;
		conn->channel_valid = false;
	}

	log_debug("[%s] Sending NABU_MSG_CONFIRMED.", conn->name);
	conn_send_byte(conn, NABU_MSG_CONFIRMED);
}

/*
 * adaptor_event_loop --
 *	Main event loop for the Adaptor emulation.
 */
void
adaptor_event_loop(struct nabu_connection *conn)
{
	uint8_t msg;
	ssize_t msglen;

	log_info("[%s] Connection starting.", conn->name);

	for (;;) {
		/* We want to block "forever" waiting for requests. */
		conn_stop_watchdog(conn);

		msglen = conn_recv(conn, &msg, 1);
		if (msglen <= 0) {
			log_error("[%s] conn_recv() returned %zd, "
			    "exiting event loop.", conn->name, msglen);
			break;
			if (conn->cancelled) {
				log_info("[%s] Received cancellation request.",
				    conn->name);
				break;
			}
			if (conn->aborted) {
				log_error("[%s] Connection aborted.",
				    conn->name);
				break;
			}
		}

		/*
		 * Now that we've got a request, we don't want any given
		 * I/O to take longer than 10 seconds.
		 */
		conn_start_watchdog(conn, 10);

		switch (msg) {
		case 0:
		case 0x0f:
		case 0x1c:
		case 0x8f:
		case 0xef:
		case 0xff:
			log_debug("[%s] Got mystery message 0x%02x.",
			    conn->name, msg);
			continue;

		default:
			log_error("[%s] Got unexpected message 0x%02x.",
			    conn->name, msg);
			continue;

		case NABU_MSG_CHANNEL_STATUS:
			log_debug("[%s] Got NABU_MSG_CHANNEL_STATUS.",
			    conn->name);
			adaptor_msg_channel_status(conn);
			continue;

		case NABU_MSG_READY:
			log_debug("[%s] Got NABU_MSG_READY.", conn->name);
			adaptor_msg_ready(conn);
			continue;

		case 0x1e:
			log_debug("[%s] Got message 0x%02x.",
			    conn->name, msg);
			adaptor_msg_1e(conn);
			continue;

		case NABU_MSG_WAIT:
			log_debug("[%s] Got NABU_MSG_WAIT.", conn->name);
			adaptor_msg_wait(conn);
			continue;

		case NABU_MSG_STARTING_UP:
			log_debug("[%s] Got NABU_MSG_STARTING_UP.", conn->name);
			adaptor_msg_starting_up(conn);
			continue;

		case NABU_MSG_INITIALIZE:
			log_debug("[%s] Got NABU_MSG_INITIALIZE.", conn->name);
			adaptor_msg_initialize(conn);
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
		}
	}
}
