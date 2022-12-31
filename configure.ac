#
# Process this file with autoconf to produce a configure script.
#

m4_define([nabud_VERSION], [0.6])

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
	[WARNCFLAGS="-Werror -Wall -Wpointer-arith"
	 AC_MSG_RESULT([yes; adding to CFLAGS: "$WARNCFLAGS"])],
	[WARNCFLAGS=""
	 AC_MSG_RESULT([no])])
AC_SUBST([WARNCFLAGS])

# Check for OpenSSL
#
m4_include([ax_check_openssl.m4])
AX_CHECK_OPENSSL([AC_DEFINE([HAVE_OPENSSL], [1],
			    [Define to 1 if you have OpenSSL.])],
	[AC_MSG_ERROR([Missing OpenSSL])])

# Check for which crypto (md5 + des) library to use for PAK files.
#
# We look for <CommonCrypto/CommonCrypto.h>, which is the native
# API on macOS.  Otherwise, we fall back to OpenSSL's libcrypto.
#
AC_CHECK_HEADER([CommonCrypto/CommonCrypto.h],
	[AC_DEFINE([HAVE_COMMONCRYPTO_H], [1],
		   [Define to 1 if you have <<CommonCrypto/CommonCrypto.h>])
	 PAK_DECRYPT_LDFLAGS=""
	 PAK_DECRYPT_LIBS=""
	 PAK_DECRYPT_INCLUDES=""],
	[PAK_DECRYPT_LDFLAGS="$OPENSSL_LDFLAGS"
	 PAK_DECRYPT_LIBS="-lcrypto"
	 PAK_DECRYPT_INCLUDES="$OPENSSL_INCLUDES"]
)
AC_SUBST([PAK_DECRYPT_LDFLAGS])
AC_SUBST([PAK_DECRYPT_LIBS])
AC_SUBST([PAK_DECRYPT_INCLUDES])

# Check for POSIX threads
#
m4_include([ax_pthread.m4])
AX_PTHREAD([],
	[AC_MSG_ERROR([Missing POSIX threads])])

# Generate the Makefiles
#
AC_CONFIG_FILES([
	Makefile
	libmj/Makefile
	nabud/Makefile
])

AC_OUTPUT

# Display feature results
#
AC_MSG_NOTICE([ === Configuration results ===])
AC_MSG_NOTICE([Version:                  $PACKAGE_VERSION])
AC_MSG_NOTICE([C compiler:               $CC])
AC_MSG_NOTICE([POSIX threads C compiler: $PTHREAD_CC])
AC_MSG_NOTICE([POSIX threads CFLAGS:     $PTHREAD_CFLAGS])
AC_MSG_NOTICE([POSIX threads libraries:  $PTHREAD_LIBS])
AC_MSG_NOTICE([Warning CFLAGS:           $WARNCFLAGS])
AC_MSG_NOTICE([OpenSSL includes:         $OPENSSL_INCLUDES])
AC_MSG_NOTICE([OpenSSL libraries:        $OPENSSL_LIBS])
AC_MSG_NOTICE([OpenSSL LDFLAGS:          $OPENSSL_LDFLAGS])
AC_MSG_NOTICE([PAK decrypt includes:     $PAK_DECRYPT_INCLUDES])
AC_MSG_NOTICE([PAK decrypt libraries:    $PAK_DECRYPT_LIBS])
AC_MSG_NOTICE([PAK decrypt LDFLAGS:      $PAK_DECRYPT_LDFLAGS])
AC_MSG_NOTICE([=============================])
