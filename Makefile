PROG=		nabud
#SRCS=		adaptor.c conn.c image.c log.c main.c mj.c
OBJS=		adaptor.o conn.o image.o log.o main.o mj.o
HDRS=		adaptor.h conn.h image.h log.h mj.h mj_defs.h nabu_proto.h \
		nbsd_queue.h

CLEANFILES=	${PROG} ${OBJS} *.core

#PTHREAD_FLAG	-pthread
CWARNFLAGS=	-Wall -Wstrict-prototypes -Wmissing-prototypes \
		-Wpointer-arith -Wno-sign-compare -Wsystem-headers \
		-Wreturn-type -Wswitch -Wshadow \
		-Wcast-qual -Wwrite-strings -Wextra \
		-Wno-unused-parameter -Wno-sign-compare \
		-Wsign-compare -Wformat=2 -Wno-format-zero-length \
		-Wno-nullability-completeness \
		-Wno-expansion-to-defined \
		-Wno-typedef-redefinition \
		-Wno-deprecated-declarations \
		-Werror

#CFLAGS+=	-g -pthread
CFLAGS=		${PTHREAD_FLAG} -g -O2 -std=gnu99 ${CWARNFLAGS}

#LDFLAGS+=	-pthread
LDFLAGS=	${PTHREAD_FLAG}

#LDADD+=	-lcrypto
#DPADD+=	${LIBCRYPTO}
#LIBCRYPTO=	-lcrypto

WARNS=	4
NOMAN=	yes

#.include <bsd.prog.mk>

all: ${PROG}

${OBJS}: ${HDRS}

${PROG}: ${OBJS}
	${CC} -o ${PROG} ${OBJS} ${LIBCRYPTO}

clean:
	-rm -f ${CLEANFILES}
