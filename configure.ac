#
# Process this file with autoconf to produce a configure script.
#

m4_define([nabud_VERSION], [0.8])

AC_INIT([nabud],
	m4_defn([nabud_VERSION]),
	[Jason Thorpe <thorpej@me.com>],
	nabud-m4_defn([nabud_VERSION]),
	[https://github.com/thorpej/nabud])
AC_PREREQ(2.69)

AC_CONFIG_SRCDIR([nabud/adaptor.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_TARGET
CANONICAL_TARGET=$target
AC_SUBST([CANONICAL_TARGET])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR

LT_INIT

# Compiler characteristics
#
AC_LANG(C)
AC_MSG_CHECKING([if using gcc])
AS_IF([test "$GCC" = "yes"],
	[CFLAGS="$CFLAGS -std=gnu99"
	 WARNCFLAGS="-Werror -Wall -Wstrict-prototypes -Wmissing-prototypes \
		     -Wpointer-arith -Wno-sign-compare -Wreturn-type -Wswitch \
		     -Wshadow -Wcast-qual -Wwrite-strings \
		     -Wformat=2 -Wno-format-zero-length"
	 AC_MSG_RESULT([yes; adding to CFLAGS: "$WARNCFLAGS"])],
	[WARNCFLAGS=""
	 AC_MSG_RESULT([no])])

case "$CANONICAL_TARGET" in
	*-*-linux*)
		# Enable _GNU_SOURCE for things like asprintf(3).
		CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
		;;
esac

# MD5 is marked as deprecated on some platforms, but we're
# kind of forced to use it regardless.
WARNCFLAGS="$WARNCFLAGS -Wno-deprecated-declarations"

AC_SUBST([WARNCFLAGS])

# Check for some common system headers.
#
AC_CHECK_HEADERS([inttypes.h])

# Deal with the crypto libraries we need.
#
WITH_SSL=no
WITH_PAK=no

# Check for CommonCrypto (the native crypto library on macOS).
#
AC_CHECK_HEADER([CommonCrypto/CommonCrypto.h],
	[AC_DEFINE([HAVE_COMMONCRYPTO_H], [1],
		   [Define to 1 if you have <CommonCrypto/CommonCrypto.h>])
	 WITH_COMMONCRYPTO="CommonCrypto"])

# Check for SecureTransport (the old native SSL/TLS framework on macOS).
# It is deprecated, but we will use it until we can make libfetch use
# the Network framework.
#
AC_CHECK_HEADER([Security/SecureTransport.h],
	[AC_DEFINE([HAVE_SECURETRANSPORT], [1],
		   [Define to 1 if you have <Security/SecureTransport.h>])
	 WITH_SECURETRANSPORT="SecureTransport"])

# Check for OpenSSL
#
m4_include([m4/ax_check_openssl.m4])
AX_CHECK_OPENSSL([AC_DEFINE([HAVE_OPENSSL], [1],
			    [Define to 1 if you have OpenSSL.])]
		 WITH_OPENSSL="OpenSSL")

# Check for which SSL implementation to use.
#
if test x$WITH_SECURETRANSPORT != x; then
	WITH_SSL="$WITH_SECURETRANSPORT"
	SSL_LIBS="-framework Security -framework CoreFoundation"
elif test x$WITH_OPENSSL != x; then
	WITH_SSL="$WITH_OPENSSL"
	SSL_LDFLAGS="$OPENSSL_LDFLAGS"
	SSL_LIBS="$OPENSSL_LIBS"
	SSL_INCLUDES="$OPENSSL_INCLUDES"
else
	AC_MSG_WARN([Building without SSL support])
fi
AC_SUBST([SSL_LDFLAGS])
AC_SUBST([SSL_LIBS])
AC_SUBST([SSL_INCLUDES])

# Check for which crypto (md5 + des) library to use for PAK files.
#
if test x$WITH_COMMONCRYPTO != x; then
	WITH_PAK="$WITH_COMMONCRYPTO"
elif test x$WITH_OPENSSL != x; then
	WITH_PAK="$WITH_OPENSSL"
	PAK_LDFLAGS="$OPENSSL_LDFLAGS"
	PAK_LIBS="-lcrypto"
	PAK_INCLUDES="$OPENSSL_INCLUDES"
else
	AC_MSG_WARN([Building without PAK file support])
fi
AC_SUBST([PAK_LDFLAGS])
AC_SUBST([PAK_LIBS])
AC_SUBST([PAK_INCLUDES])

# Check for POSIX threads
#
m4_include([m4/ax_pthread.m4])
AX_PTHREAD([],
	[AC_MSG_ERROR([Missing POSIX threads])])

# Check for struct sockaddr_un::sun_len.
#
AC_MSG_CHECKING(for sun_len member in struct sockaddr_un)
AC_COMPILE_IFELSE([
	AC_LANG_PROGRAM([[
		#include <sys/socket.h>
		#include <sys/un.h>
	]],[[
		struct sockaddr_un dummy;
		dummy.sun_len = 0;
	]])],[
		AC_DEFINE(HAVE_SOCKADDR_UN_SUN_LEN, 1, [Define if the struct sockaddr_un has a member sun_len on your OS])
		AC_MSG_RESULT(yes)],[
		AC_MSG_RESULT(no)])

# Check for some useful BSD functions that, sadly, are not universal.
#
AC_CHECK_FUNCS(getprogname)

# Generate the Makefiles
#
AC_CONFIG_FILES([
	Makefile
	libfetch/Makefile
	libmj/Makefile
	libnabud/Makefile
	nabud/Makefile
	nabuclient/Makefile
	nabuctl/Makefile
])

AC_OUTPUT

# Display feature results
#
AC_MSG_NOTICE([ === Configuration results ===])
AC_MSG_NOTICE([Version:                  $PACKAGE_VERSION])
AC_MSG_NOTICE([Installation prefix:      $prefix])
AC_MSG_NOTICE([C compiler:               $CC])
AC_MSG_NOTICE([POSIX threads C compiler: $PTHREAD_CC])
AC_MSG_NOTICE([POSIX threads CFLAGS:     $PTHREAD_CFLAGS])
AC_MSG_NOTICE([POSIX threads libraries:  $PTHREAD_LIBS])
AC_MSG_NOTICE([Warning CFLAGS:           $WARNCFLAGS])
AC_MSG_NOTICE([SSL support:              $WITH_SSL])
AC_MSG_NOTICE([SSL includes:             $SSL_INCLUDES])
AC_MSG_NOTICE([SSL libraries:            $SSL_LIBS])
AC_MSG_NOTICE([SSL LDFLAGS:              $SSL_LDFLAGS])
AC_MSG_NOTICE([PAK file support:         $WITH_PAK])
AC_MSG_NOTICE([PAK file includes:        $PAK_INCLUDES])
AC_MSG_NOTICE([PAK file libraries:       $PAK_LIBS])
AC_MSG_NOTICE([PAK file LDFLAGS:         $PAK_LDFLAGS])
AC_MSG_NOTICE([=============================])
