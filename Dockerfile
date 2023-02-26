FROM alpine:3.17 AS base

# Create a build environment
FROM base AS builder

WORKDIR /nabud

# Install necessary build tools
RUN set -eux; \
    apk add --no-cache \
    gcc \
    libc-dev \
    openssl-dev \
    readline-dev \
    libedit-dev \
    make

# Copy all source files
COPY . ./

RUN set -eux; \
    ./configure --prefix= CFLAGS='-DNABUD_CONF=\"/etc/nabud/nabud.conf\"'; \
    make

FROM base as runner

RUN set -eux; \
    apk add --no-cache \
    readline \
    libedit

ARG UID=901
ARG GID=901
ARG LIBDIR=/var/lib/nabud

# Create dedicated user
RUN set -eux; \
    addgroup -g $GID nabu; \
    adduser -u $UID -D -G nabu -H -h /home/nabu nabu; \
    mkdir -p $LIBDIR/channels $LIBDIR/storage /home/nabu; \
    ln -s $LIBDIR/* /home/nabu; \
    chown -R nabu:nabu $LIBDIR /home/nabu

COPY --from=builder /nabud/nabud/nabud /sbin
COPY --from=builder /nabud/nabuctl/nabuctl /bin
COPY --from=builder /nabud/examples/nabud.conf /etc/nabud/nabud.conf

VOLUME $LIBDIR

EXPOSE 5816/tcp

ENTRYPOINT ["/sbin/nabud"]
CMD ["-f", "-u", "nabu"]
