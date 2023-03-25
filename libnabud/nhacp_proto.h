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
 * The appliation on the NABU tells the server to go into NHACP (0.0)
 * mode by sending this message while in legacy mode.
 */
#define	NABU_MSG_START_NHACP_0_0	0xaf

/*
 * The application on the NABU tells the server that an NHACP (>= 0.1)
 * request frame follows by sending this message.
 */
#define	NABU_MSG_NHACP_REQUEST		0x8f

#define	NHACP_MAGIC_IS_VALID(cp)	((cp)[0] == 'A' &&	\
					 (cp)[1] == 'C' &&	\
					 (cp)[2] == 'P')

#define	NHACP_OPTION_CRC8		0x0001	/* Use CRC-8/WCDMA FCS */

#define	NHACP_SESSION_SYSTEM		0x00	/* Special "system" session */
#define	NHACP_SESSION_CREATE		0xff	/* Create a new session */

#define	NHACP_REQ_HELLO			0x00
#define	NHACP_REQ_STORAGE_OPEN		0x01
#define	NHACP_REQ_STORAGE_GET		0x02
#define	NHACP_REQ_STORAGE_PUT		0x03
#define	NHACP_REQ_GET_DATE_TIME		0x04
#define	NHACP_REQ_FILE_CLOSE		0x05
#define	NHACP_REQ_GET_ERROR_DETAILS	0x06
#define	NHACP_REQ_STORAGE_GET_BLOCK	0x07
#define	NHACP_REQ_STORAGE_PUT_BLOCK	0x08
#define	NHACP_REQ_FILE_READ		0x09
#define	NHACP_REQ_FILE_WRITE		0x0a
#define	NHACP_REQ_FILE_SEEK		0x0b
#define	NHACP_REQ_LIST_DIR		0x0c
#define	NHACP_REQ_GET_DIR_ENTRY		0x0d
#define	NHACP_REQ_REMOVE		0x0e
#define	NHACP_REQ_RENAME		0x0f
#define	NHACP_REQ_END_PROTOCOL_0_0	0xef
#define	NHACP_REQ_GOODBYE		0xef

/* STORAGE-OPEN flags */
#define	NHACP_O_ACCMODE		0x0007	/* mask for access mode */
#define	NHACP_O_RDONLY		0x0000	/* open only for reading */
#define	NHACP_O_RDWR		0x0001	/* open for reading + writing */
#define	NHACP_O_RDWP		0x0002	/* RDWR + lazy write-protect */
#define	NHACP_O_DIRECTORY	0x0008	/* 1=must be dir, 0=must be reg */
#define	NHACP_O_CREAT		0x0010	/* create file if it does not exist */
#define	NHACP_O_EXCL		0x0020	/* fail create if file already exists */

/* REMOVE-FILE flags */
#define	NHACP_REMOVE_FILE	0x0000	/* remove a regular file */
#define	NHACP_REMOVE_DIR	0x0001	/* remove a directory */

#define	NHACP_REMOVE_TYPEMASK	(NHACP_REMOVE_FILE | NHACP_REMOVE_DIR)

/*
 * NHACP complex types, shared by multiple request/response messages.
 */

struct nhacp_date_time {
	uint8_t		yyyymmdd[8];	/* char string */
	uint8_t		hhmmss[6];	/* char string */
};

struct nhacp_file_attrs {
	struct nhacp_date_time mtime;
	uint8_t		flags[2];	/* u16 */
	uint8_t		file_size[4];	/* u32 */
};

/* attribute flags */
#define	NHACP_AF_RD		0x0001	/* file is readable */
#define	NHACP_AF_WR		0x0002	/* file is writable */
#define	NHACP_AF_DIR		0x0004	/* file is a directory */
#define	NHACP_AF_SPEC		0x0008	/* file is a "special" file */

struct nhacp_request {
	/*
	 * NHACP >= 0.1 includes a session ID just before the length,
	 * but we don't include that here in the request structure in
	 * order to make 0.0 compatibility easier.
	 */
	uint8_t		length[2];	/* u16: length of what follows */
	union {
		struct nhacp_request_generic {
			uint8_t		type;
		} generic;
		struct nhacp_request_max {
			uint8_t		type;
			uint8_t		payload[NHACP_MAX_MESSAGELEN - 1];
		} max_request;
		struct nhacp_request_hello {
			uint8_t		type;
			uint8_t		magic[3];	/* "ACP" */
			uint8_t		version[2];	/* u16 */
			uint8_t		options[2];	/* u16 */
		} hello;
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
		struct nhacp_request_file_close {
			uint8_t		type;
			uint8_t		slot;
		} file_close;
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
		struct nhacp_request_file_read {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		flags[2];	/* u16 */
			uint8_t		length[2];	/* u16 */
		} file_read;
		struct nhacp_request_file_write {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		flags[2];	/* u16 */
			uint8_t		length[2];	/* u16 */
			uint8_t		data[];
		} file_write;
		struct nhacp_request_file_seek {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		offset[4];	/* s32 */
			uint8_t		whence;
		} file_seek;
		struct nhacp_request_list_dir {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		pattern_length;
			uint8_t		pattern[];
		} list_dir;
		struct nhacp_request_get_dir_entry {
			uint8_t		type;
			uint8_t		slot;
			uint8_t		max_name_length;
		} get_dir_entry;
		struct nhacp_request_remove {
			uint8_t		type;
			uint8_t		flags[2];	/* u16 */
			uint8_t		url_length;
			uint8_t		url_string[];
		} remove;
		struct nhacp_request_rename {
			uint8_t		type;
			/*
			 * The names buffer is structured like:
			 *
			 * uint8_t	old_name_length;
			 * uint8_t	old_name[];
			 * uint8_t	new_name_length;
			 * uint8_t	new_name[];
			 */
			uint8_t		names[];	/* old, new */
		} rename;
		struct nhacp_request_goodbye {	/* END-PROTOCOL in 0.0 */
			uint8_t		type;
		} goodbye;
	};
};

#define	NHACP_RESP_NHACP_STARTED_0_0	0x80
#define	NHACP_RESP_SESSION_STARTED	0x80
#define	NHACP_RESP_OK			0x81
#define	NHACP_RESP_ERROR		0x82
#define	NHACP_RESP_STORAGE_LOADED	0x83
#define	NHACP_RESP_DATA_BUFFER		0x84
#define	NHACP_RESP_DATE_TIME		0x85
#define	NHACP_RESP_DIR_ENTRY		0x86
#define	NHACP_RESP_UINT8_VALUE		0x87
#define	NHACP_RESP_UINT16_VALUE		0x88
#define	NHACP_RESP_UINT32_VALUE		0x89

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
		struct nhacp_response_nhacp_started_0_0 {
			uint8_t		type;
			uint8_t		version[2];	/* u16 */
			uint8_t		adapter_id_length;
			uint8_t		adapter_id[];	/* char string */
		} nhacp_started_0_0;
		struct nhacp_response_session_started {
			uint8_t		type;
			uint8_t		session_id;
			uint8_t		version[2];	/* u16 */
			uint8_t		adapter_id_length;
			uint8_t		adapter_id[];	/* char string */
		} session_started;
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
			struct nhacp_date_time date_time;
		} date_time;
		struct nhacp_response_dir_entry {
			uint8_t		type;
			struct nhacp_file_attrs attrs;
			uint8_t		name_length;
			uint8_t		name[];
		} dir_entry;
		struct nhacp_response_uint8_value {
			uint8_t		type;
			uint8_t		value;
		} uint8_value;
		struct nhacp_response_uint16_value {
			uint8_t		type;
			uint8_t		value[2];	/* u16 */
		} uint16_value;
		struct nhacp_response_uint32_value {
			uint8_t		type;
			uint8_t		value[4];	/* u32 */
		} uint32_value;
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
#define	NHACP_ENOTEMPTY		17	/* Directory is not empty */
#define	NHACP_ESRCH		18	/* No such process/session */
#define	NHACP_ENSESS		19	/* Too many sessions */
#define	NHACP_EAGAIN		20	/* Try again later */
#define	NHACP_EROFS		21	/* Object is write-protected */

/* FILE-SEEK whence values */
#define	NHACP_SEEK_SET		0
#define	NHACP_SEEK_CUR		1
#define	NHACP_SEEK_END		2

#endif /* nhacp_proto_h_included */
