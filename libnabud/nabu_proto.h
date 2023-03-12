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

#ifndef nabu_proto_h_included
#define	nabu_proto_h_included

#include <stdbool.h>
#include <stdint.h>

/*
 * Definitions for the NABU <--> Adaptor protocol.
 *
 * Adapted by Jason R. Thorpe from NabuNetworkEmulator (Constants.cs and
 * Messages.cs) by Nick Daniels.
 */

#define	NABU_MAXSEGMENTSIZE	65536
#define	NABU_MAXPACKETSIZE	1024
#define	NABU_MAXPAYLOADSIZE	991
#define	NABU_HEADERSIZE		16
#define	NABU_FOOTERSIZE		2
#define	NABU_TOTALPAYLOADSIZE	(NABU_MAXPAYLOADSIZE + NABU_HEADERSIZE + \
				 NABU_FOOTERSIZE)

#define	NABU_TIMESTAMPSIZE	9

#define	NABU_PAK_KEY							\
	{ 0x6e, 0X58, 0X61, 0X32, 0X62, 0X79, 0X75, 0X7a }

#define	NABU_PAK_IV							\
	{ 0X0c, 0X15, 0X2b, 0X11, 0X39, 0X23, 0X43, 0X1b }

#define	NABU_MSG_RESET		0x80
#define	NABU_MSG_MYSTERY	0x81
#define	NABU_MSG_GET_STATUS	0x82
#define	NABU_MSG_START_UP	0x83
#define	NABU_MSG_PACKET_REQUEST	0x84
#define	NABU_MSG_CHANGE_CHANNEL	0x85

#define	NABU_MSG_CLASSIC_FIRST	NABU_MSG_RESET
#define	NABU_MSG_CLASSIC_LAST	NABU_MSG_CHANGE_CHANNEL

#define	NABU_MSG_IS_CLASSIC(x)	((x) >= NABU_MSG_CLASSIC_FIRST &&	\
				 (x) <= NABU_MSG_CLASSIC_LAST)

#define	NABU_SERVICE_UNAUTHORIZED 0x90
#define	NABU_SERVICE_AUTHORIZED	0x91

#define	NABU_MSG_ESCAPE		0x10

#define	NABU_STATUS_SIGNAL	0x01
#define	NABU_STATUS_READY	0x05
#define	NABU_STATUS_GOOD	0x06
#define	NABU_STATUS_TRANSMIT	0x1e

#define	NABU_STATE_CONFIRMED	0xe4
#define	NABU_STATE_DONE		0xe1

#define	NABU_SIGNAL_STATUS_NO	0x9f
#define	NABU_SIGNAL_STATUS_YES	0x1f

#define	NABU_MSGSEQ_ACK							\
	{ NABU_MSG_ESCAPE, NABU_STATUS_GOOD }

#define	NABU_MSGSEQ_FINISHED						\
	{ NABU_MSG_ESCAPE, NABU_STATE_DONE }

/* Magic image number used when sending time packets. */
#define	NABU_IMAGE_TIME		0x007fffff

/*
 * The NABU Adaptor packet header.
 */
struct nabu_pkthdr {
	uint8_t		image[3];	/* image number; big-endian */
	uint8_t		segment_lsb;	/* segment LSB */
	uint8_t		owner;		/* owner */
	uint8_t		tier[4];	/* tier; big endian */
	uint8_t		mystery[2];	/* mystery bytes */
	uint8_t		type;		/* packet type / flags */
	uint8_t		segment[2];	/* segment number; little-endian */
	uint8_t		offset[2];	/* offset; big-endian */
};

struct nabu_time {
	uint8_t		mystery[2];
	uint8_t		week_day;
	uint8_t		year;
	uint8_t		month;
	uint8_t		month_day;
	uint8_t		hour;
	uint8_t		minute;
	uint8_t		second;
};

#ifdef NABU_PROTO_INLINES

/*
 * nabu_get_uint16 --
 *	Get a 16-bit integer from the specified buffer.
 */
static inline uint16_t
nabu_get_uint16(const uint8_t *buf)
{
	/* little-endian */
	return buf[0] | (buf[1] << 8);
}

/*
 * nabu_get_uint16_be --
 *	Get a 16-bit big-endian integer from the specified buffer.
 */
static inline uint16_t
nabu_get_uint16_be(const uint8_t *buf)
{
	return (buf[0] << 8) | buf[1];
}

/*
 * nabu_get_uint24 --
 *	Get a 24-bit integer from the specified buffer.
 */
static inline uint32_t
nabu_get_uint24(const uint8_t *buf)
{
	/* little-endian */
	return buf[0] | (buf[1] << 8) | (buf[2] << 16);
}

/*
 * nabu_get_uint24_be --
 *	Get a 24-bit big-endian integer from the specified buffer.
 */
static inline uint32_t
nabu_get_uint24_be(const uint8_t *buf)
{
	return (buf[0] << 16) | (buf[1] << 8) | buf[2];
}

/*
 * nabu_get_uint32 --
 *	Get a 32-bit integer from the specified buffer.
 */
static inline uint32_t
nabu_get_uint32(const uint8_t *buf)
{
	/* little-endian */
	return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

/*
 * nabu_get_uint32_be --
 *	Get a 32-bit big-endian integer from the specified buffer.
 */
static inline uint32_t
nabu_get_uint32_be(const uint8_t *buf)
{
	return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

/*
 * nabu_set_uint16 --
 *	Set a 16-bit integer in the specified buffer.
 */
static inline void
nabu_set_uint16(uint8_t *buf, uint16_t val)
{
	/* little-endian */
	buf[0] = (uint8_t)(val);
	buf[1] = (uint8_t)(val >> 8);
}

/*
 * nabu_set_uint16_be --
 *	Set a 16-bit big-endian integer in the specified buffer.
 */
static inline void
nabu_set_uint16_be(uint8_t *buf, uint16_t val)
{
	buf[0] = (uint8_t)(val >> 8);
	buf[1] = (uint8_t)(val);
}

/*
 * nabu_set_uint24 --
 *	Set a 24-bit integer in the specified buffer.
 */
static inline void
nabu_set_uint24(uint8_t *buf, uint32_t val)
{
	/* little-endian */
	buf[0] = (uint8_t)(val);
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val >> 16);
}

/*
 * nabu_set_uint24_be --
 *	Set a 24-bit big-endian integer in the specified buffer.
 */
static inline void
nabu_set_uint24_be(uint8_t *buf, uint32_t val)
{
	buf[0] = (uint8_t)(val >> 16);
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val);
}

/*
 * nabu_set_uint32 --
 *	Set a 32-bit integer in the specified buffer.
 */
static inline void
nabu_set_uint32(uint8_t *buf, uint32_t val)
{
	buf[0] = (uint8_t)(val);
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val >> 16);
	buf[3] = (uint8_t)(val >> 24);
}

/*
 * nabu_set_uint32_be --
 *	Set a 32-bit big-endian integer in the specified buffer.
 */
static inline void
nabu_set_uint32_be(uint8_t *buf, uint32_t val)
{
	buf[0] = (uint8_t)(val >> 24);
	buf[1] = (uint8_t)(val >> 16);
	buf[2] = (uint8_t)(val >> 8);
	buf[3] = (uint8_t)(val);
}

/*
 * nabu_init_pkthdr --
 *	Initialize a NABU packet header.
 */
static inline size_t
nabu_init_pkthdr(void *vbuf, uint32_t image, uint16_t segment,
    uint16_t offset, bool last)
{
	struct nabu_pkthdr *hdr = vbuf;

	nabu_set_uint24_be(hdr->image, image);
	hdr->segment_lsb = (uint8_t)segment;
	hdr->owner = 0x01;
	nabu_set_uint32_be(hdr->tier, 0x7fffffff);
	hdr->mystery[0] = 0x7f;
	hdr->mystery[1] = 0x80;
	hdr->type = (segment == 0 ? 0xa1 : 0x20) |
		    (last         ? 0x10 : 0x00);
	nabu_set_uint16(hdr->segment, segment);
	nabu_set_uint16_be(hdr->offset, offset);

	return sizeof(*hdr);
}

/*
 * nabu_set_crc --
 *	Write the packet CRC into the packet buffer.
 */
static inline size_t
nabu_set_crc(void *vbuf, uint16_t crc)
{
	uint8_t *buf = vbuf;

	buf[0] = (uint8_t)(crc >> 8);	/* CRC MSB */
	buf[1] = (uint8_t)(crc);	/* CRC LSB */

	return sizeof(crc);
}

/*
 * nabu_get_crc --
 *	Extract the CRC from the packet buffer.
 */
static inline uint16_t
nabu_get_crc(const void *vbuf)
{
	const uint8_t *buf = vbuf;

	return (buf[0] << 8) | buf[1];
}

#endif /* NABU_PROTO_INLINES */

#endif /* nabu_proto_h_included */
