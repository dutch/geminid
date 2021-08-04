EXTRA_DIST = %D%/geminid.service.in
DISTCLEANFILES = %D%/geminid.service

if HAVE_SYSTEMD
systemdsystemunit_DATA = %D%/geminid.service
endif

%D%/geminid.service: %D%/geminid.service.in
	$(MKDIR_P) %D% && $(SED) -e 's|@bindir[@]|$(bindir)|' -e 's|@runstatedir[@]|$(runstatedir)|' $< >$@.tmp && mv $@.tmp $@
