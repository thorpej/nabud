AM_CFLAGS		= $(PTHREAD_CFLAGS) $(WARNCFLAGS)
CC			= $(PTHREAD_CC)

bin_PROGRAMS		= nabud

nabud_SOURCES		= adaptor.c conn.c image.c main.c retronet.c

nabud_CPPFLAGS		= $(SSL_INCLUDES) $(PAK_INCLUDES)

nabud_LDADD		= ../libnabud/libnabud.la \
			  ../libfetch/libfetch.la \
			  ../libmj/libmj.la \
			  $(SSL_LDFLAGS) $(SSL_LIBS) \
			  $(PAK_LDFLAGS) $(PAK_LIBS) \
			  $(PTHREAD_LIBS)
