AC_INIT([geminid],
[m4_esyscmd([build-aux/git-version-gen .tarball-version])],
[https://github.com/dutch/geminid/issues], [],
[https://github.com/dutch/geminid])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19])
GEMINID_INIT
AC_PROG_CC
AC_PROG_SED
PKG_CHECK_MODULES([OPENSSL], [openssl], [], [:])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
