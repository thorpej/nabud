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

#ifndef nhacp_proto_h_included
#define	nhacp_proto_h_included

#include <stdbool.h>
#include <stdint.h>

/*
 * Definitions for the NABU HCCA Application Communication Protocol.
 *
 *    https://github.com/hanshuebner/nabu-figforth/blob/main/nabu-comms.md
 */

/*
 * NHACP protocol versions.
 */
#define	NHACP_VERS_0_0		0x0000	/* original version */
#define	NHACP_VERS_0_1		0x0001	/* NHACP 0.1 */

#define	NHACP_VERS_MAJOR(x)	(((x) >> 8) & 0xff)
#define	NHACP_VERS_MINOR(x)	( (x)       & 0xff)

/*
 * The NHACP MTU is chosen to allow a given message to fit within
 * the allotted 1 second time limit, and also satisfies the constraint
 * that the lengh field never have the MSB set, which aids in crash
 * recovery.
 */
#define	NHACP_MTU			8256
#define	NHACP_MAX_PAYLOAD		8192

/*
 * This was the max message size in the original NHACP draft.  It did
 * not ensure that the entire message was transmitted within 1 second.
 */
#define	NHACP_MTU_0_0			0x7fff

/*
 * This is the largest of the two MTU values, for buffer allocation
 * purposes.
 */
#define	NHACP_MAX_MESSAGELEN		NHACP_MTU_0_0

/*
 * The appliation on the NABU tells the server to go into NHACP
 * mode by sending this message while in legacy mode.
 */
#define	NABU_MSG_START_NHACP_0_0	0xaf
#define	NABU_MSG_START_NHACP		0x8f

/*
 * This message is received outside of the standard NHACP message
 * framing protocol.
 */
struct nabu_msg_start_nhacp {
	uint8_t		type;
	uint8_t		magic[3];	/* "ACP" */
	uint8_t		version[2];	/* u16: protocol version */
	uint8_t		options[2];	/* u16: protocol options */
};

#define	NHACP_MAGIC_IS_VALID(cp)	((cp)[0] == 'A' &&	\
					 (cp)[1] == 'C' &&	\
					 (cp)[2] == 'P')

#define	NHACP_REQ_STORAGE_OPEN		0x01
#define	NHACP_REQ_STORAGE_GET		0x02
#define	NHACP_REQ_STORAGE_PUT		0x03
#define	NHACP_REQ_GET_DATE_TIME		0x04
#define	NHACP_REQ_STORAGE_CLOSE		0x05
#define	NHACP_REQ_GET_ERROR_DETAILS	0x06
#define	NHACP_REQ_STORAGE_GET_BLOCK	0x07
#define	NHACP_REQ_STORAGE_PUT_BLOCK	0x08
#define	NHACP_REQ_END_PROTOCOL		0xef

/* STORAGE-OPEN flags */
#define	NHACP_O_RDWR		0x0000	/* open for reading + writing */
#define	NHACP_O_RDONLY		0x0001	/* open only for reading */
#define	NHACP_O_CREAT		0x0002	/* create file if it does not exist */
#define	NHACP_O_EXCL		0x0004	/* fail create if file already exists */

#define	NHACP_O_ACCMASK		(NHACP_O_RDWR | NHACP_O_RDONLY)

struct nhacp_request {
	uint8_t		length[2];	/* u16: length of what follows */
	union {
		struct nhacp_request_generic {
			uint8_t		type;
		} generic;
		struct nhacp_request_max {
			uint8_t		type;
			uint8_t		payload[NHACP_MAX_MESSAGELEN - 1];
		} max_request;
		struct nhacp_request_storage_open {
			uint8_t		type;
			uint8_t		req_slot;
			uint8_t		flags[2];	/* u16 */
			uint8_t		url_length;
			uint8_t		url_string[];	/* char string */
		} storage_open;
		struct nhacp_request_storage_get {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		offset[4];	/* u32 */
			uint8_t		length[2];	/* u16 */
		} storage_get;
		struct nhacp_request_storage_put {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		offset[4];	/* u32 */
			uint8_t		length[2];	/* u16 */
			uint8_t		data[];
		} storage_put;
		struct nhacp_request_get_date_time {
			uint8_t		type;
		} get_date_time;
		struct nhacp_request_storage_close {
			uint8_t		type;
			uint8_t		slot;
		} storage_close;
		struct nhacp_request_get_error_details {
			uint8_t		type;
			uint8_t		code[2];	/* u16 */
			uint8_t		max_message_len;
		} get_error_details;
		struct nhacp_request_storage_get_block {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		block_number[4];/* u32 */
			uint8_t		block_length[2];/* u16 */
		} storage_get_block;
		struct nhacp_request_storage_put_block {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		block_number[4];/* u32 */
			uint8_t		block_length[2];/* u16 */
			uint8_t		data[];
		} storage_put_block;
		struct nhacp_request_end_protocol {
			uint8_t		type;
		} end_protocol;
	};
};

#define	NHACP_RESP_NHACP_STARTED	0x80
#define	NHACP_RESP_OK			0x81
#define	NHACP_RESP_ERROR		0x82
#define	NHACP_RESP_STORAGE_LOADED	0x83
#define	NHACP_RESP_DATA_BUFFER		0x84
#define	NHACP_RESP_DATE_TIME		0x85

struct nhacp_response {
	uint8_t		length[2];	/* u16: length of what follows */
	union {
		struct nhacp_response_generic {
			uint8_t		type;
		} generic;
		struct nhacp_response_max {
			uint8_t		type;
			uint8_t		payload[NHACP_MAX_MESSAGELEN - 1];
		} max_response;
		struct nhacp_response_nhacp_started {
			uint8_t		type;
			uint8_t		version[2];	/* u16 */
			uint8_t		adapter_id_length;
			uint8_t		adapter_id[];	/* char string */
		} nhacp_started;
		struct nhacp_response_ok {
			uint8_t		type;
		} ok;
		struct nhacp_response_error {
			uint8_t		type;
			uint8_t		code[2];	/* u16 */
			uint8_t		message_length;
			uint8_t		message[];	/* char string */
		} error;
		struct nhacp_response_storage_loaded {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		length[4];	/* u32 */
		} storage_loaded;
		struct nhacp_response_data_buffer {
			uint8_t		type;
			uint8_t		length[2];	/* u16 */
			uint8_t		data[];
		} data_buffer;
		struct nhacp_response_date_time {
			uint8_t		type;
			uint8_t		yyyymmdd[8];	/* char string */
			uint8_t		hhmmss[6];	/* char string */
		} date_time;
	};
};

/* ERROR codes */
#define	NHACP_Eundefined	0	/* undefined error */
#define	NHACP_ENOTSUP		1	/* Operation is not supported */
#define	NHACP_EPERM		2	/* Operation is not permitted */
#define	NHACP_ENOENT		3	/* Requested file does not exist */
#define	NHACP_EIO		4	/* Input/output error */
#define	NHACP_EBADF		5	/* Bad file descriptor */
#define	NHACP_ENOMEM		6	/* Out of memory */
#define	NHACP_EACCES		7	/* Access denied */
#define	NHACP_EBUSY		8	/* File / resource is busy */
#define	NHACP_EEXIST		9	/* File already exists */
#define	NHACP_EISDIR		10	/* File is a directory */
#define	NHACP_EINVAL		11	/* Invalid argument / request */
#define	NHACP_ENFILE		12	/* Too many open files */
#define	NHACP_EFBIG		13	/* File is too large */
#define	NHACP_ENOSPC		14	/* Out of space */
#define	NHACP_ESEEK		15	/* Seek on non-seekable file */
#define	NHACP_ENOTDIR		16	/* File is not a directory */

#endif /* nhacp_proto_h_included */
