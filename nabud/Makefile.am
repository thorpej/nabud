AM_CFLAGS		= $(PTHREAD_CFLAGS) $(WARNCFLAGS)
CC			= $(PTHREAD_CC)

bin_PROGRAMS		= nabud

nabud_SOURCES		= adaptor.c conn.c image.c log.c main.c

nabud_CPPFLAGS		= $(PAK_DECRYPT_INCLUDES)

nabud_LDADD		= ../libfetch/libfetch.la \
			  ../libmj/libmj.la \
			  $(PAK_DECRYPT_LDFLAGS) $(PAK_DECRYPT_LIBS) \
			  $(PTHREAD_LIBS)
