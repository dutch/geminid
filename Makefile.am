SUBDIRS = po
ACLOCAL_AMFLAGS = -I m4
AM_DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

include $(srcdir)/src/Makefile.inc
include $(srcdir)/data/Makefile.inc
