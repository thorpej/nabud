AM_CFLAGS		= $(PTHREAD_CFLAGS) $(WARNCFLAGS)
CC			= $(PTHREAD_CC)

sbin_PROGRAMS		= nabud

nabud_SOURCES		= adaptor.c conn.c control.c image.c main.c nhacp.c \
			  retronet.c stext.c

nabud_CPPFLAGS		= -DINSTALL_PREFIX=\"$(prefix)\" \
			  $(SSL_INCLUDES) $(PAK_INCLUDES)

nabud_LDADD		= ../libnabud/libnabud.la \
			  ../libfetch/libfetch.la \
			  ../libmj/libmj.la \
			  $(SSL_LDFLAGS) $(SSL_LIBS) \
			  $(PAK_LDFLAGS) $(PAK_LIBS) \
			  $(PTHREAD_LIBS)

man8_MANS		= nabud.8

CLEANFILES		= nabud.8

nabud.8: nabud.8.in Makefile
	sed "s,^\..\" extras-$(EXTRAS_OS) ,,g" < nabud.8.in | \
	    sed "s,XXXsbindirXXX,$(sbindir),g" | \
	    sed "s,XXXsysconfdirXXX,$(sysconfdir),g" | \
	    sed "s,XXXdatadirXXX,$(datadir),g" > nabud.8
