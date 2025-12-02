AM_CFLAGS		= $(PTHREAD_CFLAGS) $(WARNCFLAGS)
CC			= $(PTHREAD_CC)

noinst_LTLIBRARIES	= libnabud.la

libnabud_la_CPPFLAGS	= $(CLI_INCLUDES)

libnabud_la_SOURCES	= atom.c cli.c conn_io.c crc16_genibus.c \
			  crc8_cdma2000.c fileio.c getprogname.c \
			  listing.c log.c strlcpy.c
