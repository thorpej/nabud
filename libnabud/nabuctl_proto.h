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

#ifndef nabuctl_proto_h_included
#define	nabuctl_proto_h_included

/* Default path to the nabud control channel. */
#define	NABUCTL_PATH_DEFAULT	"/tmp/nabuctl.sock"

/*
 * Each nabuctl message and each field within each message is prefixed with
 * this header.  When there are no more fields or objects to return, then
 * the type will be DONE and the length will be zero.  These are nested,
 * so listing channel descriptors looks like this:
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_LIST_CHANNELS
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_OBJ_CHANNEL
 *		[channel fields]
 *		NABUCTL_DONE			done with CHANNEL
 *		NABUCTL_OBJ_CHANNEL
 *		[channel fields]
 *		NABUCTL_DONE			done with CHANNEL
 *		NABUCTL_DONE			done with reply
 *
 * Note that ALL fields inside descriptors are represented as C strings;
 * they include NUL-termination, which is also reflected in the legnth.
 */
struct nabuctl_atom_header {
	uint32_t	tag;		/* network order */
	uint32_t	length;		/* network order */
};

#define	NABUCTL_DONE			0
#define	NABUCTL_ERROR			0x00ffffffU

#define	NABUCTL_TYPE(x)		((x) & (0xffU << 24))
#define	NABUCTL_TYPE_VOID	(0U << 24) /* length must be zero */
#define	NABUCTL_TYPE_STRING	(1U << 24) /* length includes nul */
#define	NABUCTL_TYPE_NUMBER	(2U << 24) /* encoded as a string */
#define	NABUCTL_TYPE_BLOB	(3U << 24)
#define	NABUCTL_TYPE_BOOL	(4U << 24) /* length must be one */

#define	NABUCTL_OBJ(x)		((x) & (0xffU << 16))
#define	NABUCTL_OBJ_CHANNEL	(1U << 16) /* channel fields follow */
#define	NABUCTL_OBJ_CONNECTION	(2U << 16) /* connection fields follow */

#define	NABUCTL_FLD(x)		(NABUCTL_TYPE(x) | NABUCTL_OBJ(x) | \
				 ((x) & (0xffU << 8)))
/*
 * Fields within a channel object.
 */
#define	NABUCTL_CHAN_NAME		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (1U << 8))
#define	NABUCTL_CHAN_PATH		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (2U << 8))
#define	NABUCTL_CHAN_LISTURL		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (3U << 8))
#define	NABUCTL_CHAN_DEFAULT_FILE	\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (4U << 8))
#define	NABUCTL_CHAN_NUMBER		\
		(NABUCTL_TYPE_NUMBER | NABUCTL_OBJ_CHANNEL | (5U << 8))
#define	NABUCTL_CHAN_TYPE		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (6U << 8))
#define	NABUCTL_CHAN_SOURCE		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CHANNEL | (7U << 8))
#define	NABUCTL_CHAN_RETRONET_EXTENSIONS \
		(NABUCTL_TYPE_BOOL   | NABUCTL_OBJ_CHANNEL | (8U << 8))
/*
 * Fields within a connection object.
 */
#define	NABUCTL_CONN_TYPE		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CONNECTION | (1U << 8))
#define	NABUCTL_CONN_NAME		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CONNECTION | (2U << 8))
#define	NABUCTL_CONN_CHANNEL		\
		(NABUCTL_TYPE_NUMBER | NABUCTL_OBJ_CONNECTION | (3U << 8))
#define	NABUCTL_CONN_STATE		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CONNECTION | (4U << 8))
#define	NABUCTL_CONN_SELECTED_FILE	\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CONNECTION | (5U << 8))
#define	NABUCTL_CONN_RETRONET_EXTENSIONS \
		(NABUCTL_TYPE_BOOL   | NABUCTL_OBJ_CONNECTION | (6U << 8))
#define	NABUCTL_CONN_FILE_ROOT		\
		(NABUCTL_TYPE_STRING | NABUCTL_OBJ_CONNECTION | (7U << 8))
#define	NABUCTL_CONN_BAUD		\
		(NABUCTL_TYPE_NUMBER | NABUCTL_OBJ_CONNECTION | (8U << 8))
#define	NABUCTL_CONN_STOP_BITS		\
		(NABUCTL_TYPE_NUMBER | NABUCTL_OBJ_CONNECTION | (9U << 8))
#define	NABUCTL_CONN_FLOW_CONTROL	\
		(NABUCTL_TYPE_BOOL   | NABUCTL_OBJ_CONNECTION | (10U << 8))

/*
 * NABUCTL_REQ_HELLO
 *
 * Arguments: string containing the control client version numnber.
 *
 * Returns: string containing the server version numnber.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_HELLO
 *		[version number string]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_TYPE_STRING
 *		[version number string]
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_HELLO		(NABUCTL_TYPE_STRING | 1)

/*
 * NABUCTL_REQ_LIST_CHANNELS
 *
 * Arguments: none.
 *
 * Returns: array of channel objects.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_LIST_CHANNELS
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_OBJ_CHANNEL
 *		[channel fields]
 *		NABUCTL_DONE			done with CHANNEL
 *		.
 *		.
 *		.
 *		NABUCTL_OBJ_CHANNEL
 *		[channel fields]
 *		NABUCTL_DONE			done with CHANNEL
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_LIST_CHANNELS	(NABUCTL_TYPE_VOID | 2)

/*
 * NABUCTL_REQ_LIST_CONNECTIONS
 *
 * Arguments: none.
 *
 * Returns: array of connection objects.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_LIST_CONNECTIONS
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_OBJ_CONNECTION
 *		[connection fields]
 *		NABUCTL_DONE			done with CONNECTION
 *		.
 *		.
 *		.
 *		NABUCTL_OBJ_CONNECTION
 *		[connection fields]
 *		NABUCTL_DONE			done with CONNECTION
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_LIST_CONNECTIONS	(NABUCTL_TYPE_VOID | 3)

/*
 * NABUCTL_REQ_CHAN_CLEAR_CACHE
 *
 * Arguments: channel numeber.
 *
 * Returns: None.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_CHAN_CLEAR_CACHE
 *		[channel number]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_CHAN_CLEAR_CACHE	(NABUCTL_TYPE_NUMBER | 20)

/*
 * NABUCTL_REQ_CHAN_FETCH_LISTING
 *
 * Arguments: channel number.
 *
 * Returns: listing blob.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_CHAN_CLEAR_CACHE
 *		[channel number]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_TYPE_BLOB
 *		[listing data]
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_CHAN_FETCH_LISTING	(NABUCTL_TYPE_NUMBER | 21)

/*
 * NABUCTL_REQ_CONN_CANCEL
 *
 * Arguments: connection name.
 *
 * Returns: none.
 *
 *	nabuctl -> nabud
 *		NABUCTL_REQ_CONN_CANCEL
 *		[connection name]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_CONN_CANCEL		(NABUCTL_TYPE_STRING | 40)

/*
 * NABUCTL_REQ_CONN_CHANGE_CHANNEL
 *
 * Arguments: connection name, channel number
 *
 * Returns: connection's selected channel number.
 *
 *	nabuctl -> nabud
 *		NABUCTL_CONN_CHANGE_CHANNEL
 *		[connection name]
 *		NABUCTL_TYPE_NUMBER
 *		[channel number]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_CONN_CHANGE_CHANNEL	(NABUCTL_TYPE_STRING | 41)

/*
 * NABUCTL_REQ_CONN_SELECT_FILE
 *
 * Arguments: connection name, file name
 *
 * Returns: none.
 *
 *	nabuctl -> nabud
 *		NABUCTL_CONN_SELECT_FILE
 *		[connection name]
 *		NABUCTL_TYPE_STRING
 *		[file name]
 *		NABUCTL_DONE			done with REQUEST
 *
 *	nabuctl <- nabud
 *		NABUCTL_DONE			done with reply
 */
#define	NABUCTL_REQ_CONN_SELECT_FILE	(NABUCTL_TYPE_STRING | 42)

#endif /* nabuctl_proto_h_included */
