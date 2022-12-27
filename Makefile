PROG=	nabud
SRCS=	adaptor.c conn.c log.c main.c image.c

CFLAGS+= -pthread
LDFLAGS+= -pthread

LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}

WARNS=	4

NOMAN=	yes

.include <bsd.prog.mk>
