bin_PROGRAMS = %D%/geminid
%C%_geminid_SOURCES = %D%/main.c
%C%_geminid_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DRUNSTATEDIR='"$(runstatedir)"'

dist_man_MANS = %D%/geminid.1 %D%/geminid.conf.5
