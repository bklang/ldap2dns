# $Id$ 
VERSION=0.3.7
RELEASE=0
CC=gcc -O2
CCDEBUG=gcc -g -ggdb
CFLAGS=$(INC) -DVERSION='"$(VERSION)"'
LIBS=-lldap -llber
LD=gcc 
LDFLAGS=
INSTALL_PREFIX=
PREFIXDIR=$(INSTALL_PREFIX)/usr
LDAPCONFDIR=$(INSTALL_PREFIX)/etc/openldap
SPECFILE=ldap2dns.spec
DISTRIBUTION=redhat

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
	$(CC) $(CFLAGS) -c $< -o $@

ldap2dns.o-dbg: ldap2dns.c
	$(CCDEBUG) $(CFLAGS) -c $< -o $@

install: all
	mkdir -p $(PREFIXDIR)/bin
	mkdir -p $(LDAPCONFDIR)/schema
	install -s -o root -g root -m 755 ldap2dns $(PREFIXDIR)/bin/
	ln -f $(PREFIXDIR)/bin/ldap2dns $(PREFIXDIR)/bin/ldap2dnsd
	install -o root -g root -m 755 ldap2tinydns-conf $(PREFIXDIR)/bin/
	install -o root -g root -m 644 ldap2dns.schema $(LDAPCONFDIR)/schema/

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
	    < $(SPECFILE).in > $(SPECFILE)
		
	mv ../ldap2dns-$(VERSION).tar.gz $(RPMBASE)/SOURCES
	rpmbuild -ba $(SPECFILE)
