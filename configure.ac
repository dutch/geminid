AC_INIT([geminid],
[m4_esyscmd([build-aux/git-version-gen .tarball-version])],
[https://github.com/dutch/geminid/issues], [],
[https://github.com/dutch/geminid])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_PROG_CC
PKG_CHECK_MODULES([OPENSSL], [openssl])
#GEMINID_CHECK_OPENSSL
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
