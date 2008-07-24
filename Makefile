# $Id$ 
VERSION=0.5.0
RELEASE?=0
CC=gcc
DEBUG_CFLAGS?=-g -ggdb
CFLAGS?=-O2
LIBS?=-lldap -llber
LD=gcc 
LDFLAGS?=
INSTALL_PREFIX?=
PREFIXDIR?=/usr/local
LDAPCONFDIR?=/etc/openldap
MANDIR?=$(PREFIXDIR)/man
SPECFILE?=ldap2dns.spec
DISTRIBUTION?=redhat

ifeq "$(DISTRIBUTION)" "redhat"
RPMBASE=/usr/src/redhat
RPMGROUP=Daemons/DNS
OPENLDAPPKG=openldap
endif

ifeq "$(DISTRIBUTION)" "suse"
RPMBASE=/usr/src/packages
RPMGROUP=Productivity/Networking/DNS/Servers
OPENLDAPPKG=openldap2
endif


all: ldap2dns ldap2dnsd

debug: ldap2dns-dbg

ldap2dns: ldap2dns.o
	$(LD) $(LDFLAGS) $(LIBS) -o $@ $+

ldap2dnsd: ldap2dns
	ln -f ldap2dns ldap2dnsd

ldap2dns-dbg: ldap2dns.o-dbg
	$(LD) $(LDFLAGS) $(LIBS) -o $@ $+

ldap2dns.o: ldap2dns.c
	$(CC) $(CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

ldap2dns.o-dbg: ldap2dns.c
	$(CC) $(DEBUG_CFLAGS) $(CFLAGS) -DVERSION='"$(VERSION)"' -c $< -o $@

install: all
	mkdir -p $(INSTALL_PREFIX)/$(PREFIXDIR)/bin
	mkdir -p $(INSTALL_PREFIX)/$(LDAPCONFDIR)/schema
	mkdir -p $(INSTALL_PREFIX)/$(MANDIR)/man1
	install -s -m 755 ldap2dns $(INSTALL_PREFIX)/$(PREFIXDIR)/bin/
	ln -f $(INSTALL_PREFIX)/$(PREFIXDIR)/bin/ldap2dns \
		$(INSTALL_PREFIX)/$(PREFIXDIR)/bin/ldap2dnsd
	install -m 755 ldap2tinydns-conf $(INSTALL_PREFIX)/$(PREFIXDIR)/bin/
	install -m 644 ldap2dns.schema $(INSTALL_PREFIX)/$(LDAPCONFDIR)/schema/
	install -m 644 ldap2dns.1 $(INSTALL_PREFIX)/$(MANDIR)/man1

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
