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

#define	NABU_CRC_TAB							  \
	{ 0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, \
	  0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, \
	  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, \
	  0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de, \
	  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, \
	  0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d, \
	  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4, \
	  0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc, \
	  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823, \
	  0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b, \
	  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12, \
	  0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a, \
	  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, \
	  0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49, \
	  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, \
	  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78, \
	  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, \
	  0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067, \
	  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, \
	  0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256, \
	  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, \
	  0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, \
	  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c, \
	  0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634, \
	  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab, \
	  0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3, \
	  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, \
	  0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92, \
	  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, \
	  0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1, \
	  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, \
	  0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0 }

#define	NABU_MSG_RESET		0x80
#define	NABU_MSG_MYSTERY	0x81
#define	NABU_MSG_GET_STATUS	0x82
#define	NABU_MSG_START_UP	0x83
#define	NABU_MSG_PACKET_REQUEST	0x84
#define	NABU_MSG_CHANGE_CHANNEL	0x85
#define	NABU_MSG_BEGIN		0x8F

#define	NABU_MSG_UNAUTHORIZED	0x90
#define	NABU_MSG_AUTHORIZED	0x91

#define	NABU_MSG_ESCAPE		0x10

#define	NABU_MSG_READY		0x05
#define	NABU_MSG_GOOD		0x06
#define	NABU_MSG_CONFIRMED	0xe4
#define	NABU_MSG_DONE		0xe1

#define	NABU_MSG_CHANNEL_STATUS	0x01
#define	NABU_MSG_TRANSMIT_STATUS 0x1e

#define	NABU_MSG_NEED_CHANNEL	0x9f
#define	NABU_MSG_HAVE_CHANNEL	0x1f

/*
 * NabuRetroNet extensions.  See:
 *
 *     https://github.com/DJSures/NABU-LIB/blob/main/NABULIB/NABU-LIB.h
 *
 * ...for details.  This matches v2023.01.03.00 and is NOT compatible
 * with the original RetroNet storage extensions from v2022.12.26.00
 * (message 0xa3 changed format).
 *
 * NABU_MSG_RN_FILE_OPEN	0xa3
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *	uint16_t		fileFlag (see below)
 *	uint8_t			fileHandle (see below)
 *
 * ->   uint8_t			fileHandle
 *				N.B. This apparently always succeeds,
 *				an opening a non-existent file for
 *				reading will result in a virtual
 *				empty file.
 *
 * NABU_MSG_RN_FH_SIZE		0xa4
 *	uint8_t			fileHandle
 *
 * ->	int32_t			fileSize (-1 on failure)
 *
 * NABU_MSG_RN_FH_READ		0xa5
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *
 * ->	[length bytes]		data (padded with 0s)
 *
 * NABU_MSG_RN_FH_CLOSE		0xa7
 *	uint8_t			fileHandle
 *
 * ->	No return
 *
 * NABU_MSG_RN_FILE_SIZE	0xa8
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *
 * ->	int32_t			fileSize (-1 on failure)
 *
 * NABU_MSG_RN_FH_APPEND	0xa9
 *	uint8_t			fileHandle
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 *
 * NABU_MSG_RN_FH_INSERT	0xaa
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 *
 * NABU_MSG_RN_FH_DELETE_RANGE	0xab
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		deleteLen
 *
 * ->	No return
 *
 * NABU_MSG_RN_FH_REPLACE	0xac
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 *
 * NABU_MSG_RN_FILE_DELETE	0xad
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *
 * ->	No return
 *
 * NABU_MSG_RN_FILE_COPY	0xae
 *	uint8_t			srcFileNameLen
 *	[srcFileNameLen bytes]	srcFileName
 *	uint8_t			dstFileNameLen
 *	[dstFileNameLen bytes]	dstFileName
 *	uint8_t			copyFlags
 *
 * ->	No return
 *
 * NABU_MSG_RN_FILE_MOVE	0xaf
 *	uint8_t			srcFileNameLen
 *	[srcFileNameLen bytes]	srcFileName
 *	uint8_t			dstFileNameLen
 *	[dstFileNameLen bytes]	dstFileName
 *	uint8_t			copyFlags
 *
 * ->	No return
 *
 * NABU_MSG_RN_FH_TRUNCATE	0xb0		DJ calls this "empty file"
 *	uint8_t			fileHandle
 *
 * ->	No return
 *
 * NABU_MSG_RN_FILE_LIST	0xb1
 *	uint8_t			pathLen
 *	[pathLen bytes]		path
 *	uint8_t			patternLen
 *	[patternLen bytes]	pattern
 *	uint8_t			flags
 *
 * ->	uint16_t		matchCount
 *
 * NABU_MSG_RN_FILE_LIST_ITEM	0xb2
 *	uint16_t		itemIndex
 *
 * ->	RnFileDetails structure (83 bytes)
 */
#define	NABU_MSG_RN_FILE_OPEN	0xa3
#define	NABU_MSG_RN_FH_SIZE	0xa4
#define	NABU_MSG_RN_FH_READ	0xa5
#define	NABU_MSG_RN_FH_CLOSE	0xa7
#define	NABU_MSG_RN_FILE_SIZE	0xa8
#define	NABU_MSG_RN_FH_APPEND	0xa9
#define	NABU_MSG_RN_FH_INSERT	0xaa
#define	NABU_MSG_RN_FH_DELETE_RANGE 0xab
#define	NABU_MSG_RN_FH_REPLACE	0xac
#define	NABU_MSG_RN_FILE_DELETE	0xad
#define	NABU_MSG_RN_FILE_COPY	0xae
#define	NABU_MSG_RN_FILE_MOVE	0xaf
#define	NABU_MSG_RN_FH_TRUNCATE	0xb0
#define	NABU_MSG_RN_FILE_LIST	0xb1
#define	NABU_MSG_RN_FILE_LIST_ITEM 0xb2

	/* FILE_OPEN flags */
#define	RN_FILE_OPEN_RW		0x01

	/* COPY / MOVE flags */
#define	RN_FILE_COPY_MOVE_REPLACE 0x01

#define	NABU_MSGSEQ_ACK							\
	{ NABU_MSG_ESCAPE, NABU_MSG_GOOD }

#define	NABU_MSGSEQ_FINISHED						\
	{ NABU_MSG_ESCAPE, NABU_MSG_DONE }

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
	uint8_t		mystery[3];
	uint8_t		year;
	uint8_t		month;
	uint8_t		month_day;
	uint8_t		hour;
	uint8_t		minute;
	uint8_t		second;
};

/*
 * NabuRetroNet file details structure.
 */
struct rn_file_details {
	uint8_t		file_size[4];
#define	NR_ISDIR	((uint32_t)-1)
#define	NR_NOENT	((uint32_t)-2)

	uint8_t		c_year[2];
	uint8_t		c_month;
	uint8_t		c_day;
	uint8_t		c_hour;
	uint8_t		c_minute;
	uint8_t		c_second;

	uint8_t		m_year[2];
	uint8_t		m_month;
	uint8_t		m_day;
	uint8_t		m_hour;
	uint8_t		m_minute;
	uint8_t		m_second;

	uint8_t		name_length;
	uint8_t		name[64];
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
 * nabu_crc --
 *	Compute the CRC of the provided data buffer.
 */
static inline uint16_t
nabu_crc_update(const void *vbuf, size_t len, uint16_t crc)
{
	static const uint16_t crctab[] = NABU_CRC_TAB;
	const uint8_t *buf = vbuf;
	size_t i;
	uint8_t c;

	for (i = 0; i < len; i++) {
		c = (crc >> 8) ^ buf[i];
		crc <<= 8;
		crc ^= crctab[c];
	}
	return crc;
}

static inline uint16_t
nabu_crc_final(uint16_t crc)
{
	return crc ^ 0xffff;
}

static inline uint16_t
nabu_crc(const void *vbuf, size_t len)
{
	return nabu_crc_final(nabu_crc_update(vbuf, len, 0xffff));
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
