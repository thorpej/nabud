PROG=	nabud
SRCS=	adaptor.c conn.c image.c log.c main.c mj.c

CPPFLAGS+= -DNABUD_VERSION=\"0.5\"

CFLAGS+= -g -pthread
LDFLAGS+= -pthread

LDADD+= -lcrypto
DPADD+= ${LIBCRYPTO}

WARNS=	4

NOMAN=	yes

.include <bsd.prog.mk>
