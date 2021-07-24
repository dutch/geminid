bin_PROGRAMS = %D%/geminid
%C%_geminid_SOURCES = %D%/main.c %D%/daemon.c %D%/daemon.h %D%/parse.c %D%/parse.h
%C%_geminid_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DRUNSTATEDIR='"$(runstatedir)"' $(OPENSSL_CFLAGS)
%C%_geminid_LDADD = $(OPENSSL_LIBS)

dist_man_MANS = %D%/geminid.1 %D%/geminid.conf.5
