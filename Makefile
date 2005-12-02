# $Id: Makefile,v 1.30 2003/01/20 14:33:25 jrief Exp $ 
VERSION=0.3.4
RELEASE=1
CC=gcc -O2
CCDEBUG=gcc -g
CFLAGS=$(INC) -DVERSION='"$(VERSION)"'
LIBS=-lldap -llber
LD=gcc 
LDFLAGS=
INSTALL_PREFIX=
PREFIXDIR=$(INSTALL_PREFIX)/usr
LDAPCONFDIR=$(INSTALL_PREFIX)/etc/openldap
TARFILE=/usr/src/redhat/SOURCES/ldap2dns-$(VERSION).tar.gz
SPECFILE=ldap2dns.spec

all: ldap2dns ldap2dnsd ldap2dns-dbg

ldap2dns: ldap2dns.o $(LIBS) 
	$(LD) $(LDFLAGS) -o $@ $+

ldap2dnsd: ldap2dns
	ln -f ldap2dns ldap2dnsd

ldap2dns-dbg: ldap2dns.o-dbg $(LIBS) 
	$(LD) $(LDFLAGS) -o $@ $+

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
	install -o root -g root -m 644 dns.schema $(LDAPCONFDIR)/schema/

clean:
	rm -f *.o *.o-dbg ldap2dns ldap2dnsd data* *.db core $(SPECFILE)

tar: clean
	cd ..; \
	tar czf $(TARFILE) ldap2dns-$(VERSION) --exclude CVS 

$(SPECFILE): Specfile
	sed -e 's#%VERSION%#$(VERSION)#g' \
	    -e 's#%RELEASE%#$(RELEASE)#g' \
	    < $< > $@

rpm: tar $(SPECFILE)
	rpm -ba $(SPECFILE)


