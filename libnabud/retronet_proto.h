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

#ifndef retronet_proto_h_included
#define	retronet_proto_h_included

/*
 * Definitions for the NabuRetroNet protocol extensions.  See:
 *
 *  https://github.com/DJSures/NABU-LIB/blob/main/NABULIB/RetroNET-FileStore.h
 *
 * ...for details.  This matches v2023.02.03.00 and is NOT compatible
 * with the original RetroNet storage extensions from v2022.12.26.00
 * (message 0xa3 changed format).
 */

/*
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
 */
#define	NABU_MSG_RN_FILE_OPEN	0xa3
struct rn_file_open_req {
	uint8_t		fileNameLen;
	uint8_t		fileName[255 + 2 + 1];
};

	/* FILE_OPEN flags */
#define	RN_FILE_OPEN_RW		0x01

struct rn_file_open_repl {
	uint8_t		fileHandle;
};

/*
 * NABU_MSG_RN_FH_SIZE		0xa4
 *	uint8_t			fileHandle
 *
 * ->	int32_t			fileSize (-1 on failure)
 */
#define	NABU_MSG_RN_FH_SIZE	0xa4
struct rn_fh_size_req {
	uint8_t		fileHandle;
};

struct rn_fh_size_repl {
	uint8_t		fileSize[4];
};

/*
 * NABU_MSG_RN_FH_READ		0xa5
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *
 * ->	uint16_t		return length
 *	[return length bytes]	data
 */
#define	NABU_MSG_RN_FH_READ	0xa5
struct rn_fh_read_req {
	uint8_t		fileHandle;
	uint8_t		offset[4];
	uint8_t		length[2];
};

struct rn_fh_read_repl {
	uint8_t		returnLength[2];
	uint8_t		data[65535];
};

/*
 * NABU_MSG_RN_TELNET		0xa6
 *	Mystery TELNET message in DJ's Internet Adapter.
 */


/*
 * NABU_MSG_RN_FH_CLOSE		0xa7
 *	uint8_t			fileHandle
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_CLOSE	0xa7
struct rn_fh_close_req {
	uint8_t		fileHandle;
};

/*
 * NABU_MSG_RN_FILE_SIZE	0xa8
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *
 * ->	int32_t			fileSize (-1 on failure)
 */
#define	NABU_MSG_RN_FILE_SIZE	0xa8
struct rn_file_size_req {
	uint8_t		fileNameLen;
	uint8_t		fileName[255];
};

struct rn_file_size_repl {
	uint8_t		fileSize[4];
};

/*
 * NABU_MSG_RN_FH_APPEND	0xa9
 *	uint8_t			fileHandle
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_APPEND	0xa9
struct rn_fh_append_req {
	uint8_t		fileHandle;
	uint8_t		length[2];
	uint8_t		data[65535];
};

/*
 * NABU_MSG_RN_FH_INSERT	0xaa
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_INSERT	0xaa
struct rn_fh_insert_req {
	uint8_t		fileHandle;
	uint8_t		offset[4];
	uint8_t		length[2];
	uint8_t		data[65535];
};

/*
 * NABU_MSG_RN_FH_DELETE_RANGE	0xab
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		deleteLen
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_DELETE_RANGE 0xab
struct rn_fh_delete_range_req {
	uint8_t		fileHandle;
	uint8_t		offset[4];
	uint8_t		deleteLen[2];
};

/*
 * NABU_MSG_RN_FH_REPLACE	0xac
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint16_t		length
 *	[length bytes]		data
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_REPLACE	0xac
struct rn_fh_replace_req {
	uint8_t		fileHandle;
	uint8_t		offset[4];
	uint8_t		length[2];
	uint8_t		data[65535];
};

/*
 * NABU_MSG_RN_FILE_DELETE	0xad
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FILE_DELETE	0xad
struct rn_fh_file_delete_req {
	uint8_t		fileNameLen;
	uint8_t		fileName[255];
};

/*
 * NABU_MSG_RN_FILE_COPY	0xae
 *	uint8_t			srcFileNameLen
 *	[srcFileNameLen bytes]	srcFileName
 *	uint8_t			dstFileNameLen
 *	[dstFileNameLen bytes]	dstFileName
 *	uint8_t			copyFlags
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FILE_COPY	0xae
struct rn_file_copy_req {
	uint8_t		ugh[1 + 255 + 1 + 255 + 1];
};

/*
 * NABU_MSG_RN_FILE_MOVE	0xaf
 *	uint8_t			srcFileNameLen
 *	[srcFileNameLen bytes]	srcFileName
 *	uint8_t			dstFileNameLen
 *	[dstFileNameLen bytes]	dstFileName
 *	uint8_t			copyFlags
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FILE_MOVE	0xaf
struct rn_file_move_req {
	uint8_t		ugh[1 + 255 + 1 + 255 + 1];
};

	/* COPY / MOVE flags */
#define	RN_FILE_COPY_MOVE_REPLACE 0x01

/*
 * NABU_MSG_RN_FH_TRUNCATE	0xb0		DJ calls this "empty file"
 *	uint8_t			fileHandle
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_TRUNCATE	0xb0
struct rn_fh_truncate_req {
	uint8_t		fileHandle;
};

/*
 * NABU_MSG_RN_FILE_LIST	0xb1
 *	uint8_t			pathLen
 *	[pathLen bytes]		path
 *	uint8_t			patternLen
 *	[patternLen bytes]	pattern
 *	uint8_t			flags
 *
 * ->	uint16_t		matchCount
 */
#define	NABU_MSG_RN_FILE_LIST	0xb1
struct rn_file_list_req {
	uint8_t		ugh[1 + 255 + 1 + 255 + 1];
};

struct rn_file_list_repl {
	uint8_t		matchCount[2];
};

/*
 * NABU_MSG_RN_FILE_LIST_ITEM	0xb2
 *	uint16_t		itemIndex
 *
 * ->	RnFileDetails structure (83 bytes)
 */
#define	NABU_MSG_RN_FILE_LIST_ITEM 0xb2
struct rn_file_list_item_req {
	uint8_t		itemIndex[2];
};

/*
 * NABU_MSG_RN_FILE_DETAILS	0xb3
 *	uint8_t			fileNameLen
 *	[fileNameLen bytes]	fileName
 *
 * ->	RnFileDetails structure (83 bytes)
 */
#define	NABU_MSG_RN_FILE_DETAILS 0xb3
struct rn_file_details_req {
	uint8_t		fileNameLen;
	uint8_t		fileName[255];
};

/*
 * NABU_MSG_RN_FH_DETAILS	0xb4
 *	uint8_t			fileHandle
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_DETAILS	0xb4
struct rn_fh_details_req {
	uint8_t		fileHandle;
};

/*
 * NABU_MSG_RN_FH_READSEQ	0xb5
 *	uint8_t			fileHandle
 *
 * ->	No return
 */
#define	NABU_MSG_RN_FH_READSEQ	0xb5
struct rn_fh_readseq_req {
	uint8_t		fileHandle;
	uint8_t		length[2];
};

struct rn_fh_readseq_repl {
	uint8_t		returnLength[2];
	uint8_t		data[65535];
};

/*
 * NABU_MSG_RN_FH_SEEK		0xb6
 *	uint8_t			fileHandle
 *	uint32_t		offset
 *	uint8_t			whence
 */
#define	NABU_MSG_RN_FH_SEEK	0xb6
struct rn_fh_seek_req {
	uint8_t		fileHandle;
	uint8_t		offset[4];
	uint8_t		whence;
};

#define	RN_SEEK_SET		1
#define	RN_SEEK_CUR		2
#define	RN_SEEK_END		3

struct rn_fh_seek_repl {
	uint8_t		offset[4];
};

#define	NABU_MSG_RN_FIRST	NABU_MSG_RN_FILE_OPEN
#define	NABU_MSG_RN_LAST	NABU_MSG_RN_FH_SEEK

#define	NABU_MSG_IS_RETRONET(x)	((x) >= NABU_MSG_RN_FIRST &&	\
				 (x) <= NABU_MSG_RN_LAST)

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

#endif /* retronet_proto_h_included */
