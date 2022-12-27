PROG=	nabud
SRCS=	adaptor.c conn.c log.c main.c segment.c

CFLAGS+= -pthread
LDFLAGS+= -pthread

WARNS=	4

NOMAN=	yes

.include <bsd.prog.mk>
