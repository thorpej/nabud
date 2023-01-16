AM_CFLAGS		= $(PTHREAD_CFLAGS) $(WARNCFLAGS)
CC			= $(PTHREAD_CC)

sbin_PROGRAMS		= nabud

nabud_SOURCES		= adaptor.c conn.c control.c image.c main.c nhacp.c

nabud_CPPFLAGS		= -DINSTALL_PREFIX=\"$(prefix)\" \
			  $(SSL_INCLUDES) $(PAK_INCLUDES)

nabud_LDADD		= ../libnabud/libnabud.la \
			  ../libfetch/libfetch.la \
			  ../libmj/libmj.la \
			  $(SSL_LDFLAGS) $(SSL_LIBS) \
			  $(PAK_LDFLAGS) $(PAK_LIBS) \
			  $(PTHREAD_LIBS)
