AM_CFLAGS		= $(WARNCFLAGS)

noinst_LTLIBRARIES	= libfetch.la

libfetch_la_CPPFLAGS	= -DNETBSD -DFTP_COMBINE_CWDS -DINET6

libfetch_la_SOURCES	= fetch.c common.c ftp.c http.c file.c

ftperr.h: errlist.sh ftp.errors
	sh $(srcdir)/errlist.sh ftp_errlist FTP \
	    $(srcdir)/ftp.errors > ftperr.h

httperr.h: errlist.sh http.errors
	sh $(srcdir)/errlist.sh http_errlist HTTP \
	    $(srcdir)/http.errors > httperr.h
