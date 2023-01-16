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
 * By restricting the max message length to a singed 16-bit value, we
 * guarantee that the most significant bit of the length is never set,
 * thus easing crash recovery.
 */
#define	NHACP_MAX_MESSAGELEN		0x7fff

/*
 * The appliation on the NABU tells the server to go into NHACP
 * mode by sending this message while in legacy mode.
 */
#define	NABU_MSG_START_NHACP	0xaf

#define	NHACP_REQ_STORAGE_OPEN		0x01
#define	NHACP_REQ_STORAGE_GET		0x02
#define	NHACP_REQ_STORAGE_PUT		0x03
#define	NHACP_REQ_GET_DATE_TIME		0x04
#define	NHACP_REQ_STORAGE_CLOSE		0x05
#define	NHACP_REQ_END_PROTOCOL		0xef

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

#endif /* nhacp_proto_h_included */
