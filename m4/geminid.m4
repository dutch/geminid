# GEMINID_CHECK_OPENSSL
# ---------------------
# Something here.
AC_DEFUN([GEMINID_CHECK_OPENSSL],
[AC_CHECK_LIB([crypto], [CRYPTO_new_ex_data], [], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])])
FOUND_SSL_LIB=no
AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [FOUND_SSL_LIB=yes])
AC_CHECK_LIB([ssl], [SSL_library_init], [FOUND_SSL_LIB=yes])
AS_IF([test "x$FOUND_SSL_LIB" = xno], [AC_MSG_ERROR([library 'ssl' is required for OpenSSL])])
])
