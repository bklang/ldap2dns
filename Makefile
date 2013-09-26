VERSION=0.5.0
RELEASE?=0
DEBUG_CFLAGS?=-g -ggdb
CFLAGS?=-O2 -Wall -Werror
LIBS?=-lldap -llber
LDFLAGS?=
DESTDIR?=
PREFIXDIR?=/usr/local
LDAPCONFDIR?=/etc/ldap
MANDIR?=$(PREFIXDIR)/man
SPECFILE?=ldap2dns.spec
DISTRIBUTION?=ubuntu

ifeq "$(DISTRIBUTION)" "redhat"
LDAPCONFDIR?=/etc/openldap
RPMBASE=/usr/src/redhat
RPMGROUP=Daemons/DNS
OPENLDAPPKG=openldap
endif

ifeq "$(DISTRIBUTION)" "suse"
LDAPCONFDIR?=/etc/openldap
RPMBASE=/usr/src/packages
RPMGROUP=Productivity/Networking/DNS/Servers
OPENLDAPPKG=openldap2
endif


all: ldap2dns ldap2dnsd

debug: ldap2dns-dbg

ldap2dns: ldap2dns.o
	$(CC) -o $@ $+ $(LDFLAGS) $(LIBS) 

ldap2dnsd: ldap2dns
	ln -f ldap2dns ldap2dnsd

ldap2dns-dbg: ldap2dns.o-dbg
	$(CC) -o $@ $+ $(LDFLAGS) $(LIBS) 

ldap2dns.o: ldap2dns.c
	$(CC) $(CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

ldap2dns.o-dbg: ldap2dns.c
	$(CC) $(DEBUG_CFLAGS) $(CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

install: all
	mkdir -p $(DESTDIR)/$(PREFIXDIR)/bin
	mkdir -p $(DESTDIR)/$(CCAPCONFDIR)/schema
	mkdir -p $(DESTDIR)/$(MANDIR)/man1
	install -s -m 755 ldap2dns $(DESTDIR)/$(PREFIXDIR)/bin/
	ln -f $(DESTDIR)/$(PREFIXDIR)/bin/ldap2dns \
		$(DESTDIR)/$(PREFIXDIR)/bin/ldap2dnsd
	install -m 755 ldap2tinydns-conf $(DESTDIR)/$(PREFIXDIR)/bin/
	install -m 644 ldap2dns.schema $(DESTDIR)/$(CCAPCONFDIR)/schema/
	install -m 644 ldap2dns.1 $(DESTDIR)/$(MANDIR)/man1
	ln -f $(DESTDIR)/$(MANDIR)/man1/ldap2dns.1 \
		$(DESTDIR)/$(MANDIR)/man1/ldap2dnsd.1
	install -m 644 ldap2tinydns-conf.1 $(DESTDIR)/$(MANDIR)/man1

clean:
	rm -f *.o *.o-dbg ldap2dns ldap2dns-dbg ldap2dnsd data* *.db core \
    $(SPECFILE)

tar: clean
	cd ..; \
	mv ldap2dns ldap2dns-$(VERSION); \
	tar --exclude .svn -czf ldap2dns-$(VERSION).tar.gz ldap2dns-$(VERSION); \
	mv ldap2dns-$(VERSION) ldap2dns; \
	cd ldap2dns

rpm: tar
	sed -e 's#%VERSION%#$(VERSION)#g' \
	    -e 's#%RELEASE%#$(RELEASE)#g' \
		-e 's#%RPMGROUP%#$(RPMGROUP)#g' \
		-e 's#%OPENLDAPPKG%#$(OPENLDAPPKG)#g' \
		-e 's#%MANDIR%#$(MANDIR)#g' \
	    < $(SPECFILE).in > $(SPECFILE)
		
	mv ../ldap2dns-$(VERSION).tar.gz $(RPMBASE)/SOURCES
	rpmbuild -ba $(SPECFILE)
