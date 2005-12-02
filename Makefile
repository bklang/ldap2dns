# $Id: Makefile,v 1.22 2001/02/16 09:51:23 jrief Exp $ 
VERSION=0.2.3
RELEASE=1
CC=gcc -O2
CFLAGS=$(INC) $(WITHTINYDNS) -DVERSION='"$(VERSION)"'
OBJS=ldap2dns.o 
LIBS=-lldap -llber -lresolv
LD=gcc 
LDFLAGS=
INSTALL_PREFIX=
PREFIXDIR=$(INSTALL_PREFIX)/usr
LDAPCONFDIR=$(INSTALL_PREFIX)/etc/openldap
TARFILE=/usr/src/redhat/SOURCES/ldap2dns-$(VERSION).tar.gz
SPECFILE=ldap2dns.spec

all: ldap2dns

ldap2dns: $(OBJS) $(LIBS) 
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
	ln -f ldap2dns ldap2dnsd

ldap2dns.o: ldap2dns.c
	$(CC) $(CFLAGS) -c $<

install: all
	mkdir -p $(PREFIXDIR)/bin
	mkdir -p $(LDAPCONFDIR)
	install -s -o root -g root -m 755 ldap2dns $(PREFIXDIR)/bin/
	ln -f $(PREFIXDIR)/bin/ldap2dns $(PREFIXDIR)/bin/ldap2dnsd
	install -o root -g root -m 755 ldap2tinydns-conf $(PREFIXDIR)/bin/
	install -o root -g root -m 644 dns.at.conf $(LDAPCONFDIR)/
	install -o root -g root -m 644 dns.oc.conf $(LDAPCONFDIR)/

clean:
	rm -f $(OBJS) ldap2dns ldap2dnsd data* *.db $(SPECFILE)

tar: clean
	cd ..; \
	tar czf $(TARFILE) ldap2dns-$(VERSION) --exclude CVS --exclude DNSadmin

$(SPECFILE): Specfile
	sed -e 's#%VERSION%#$(VERSION)#g' \
	    -e 's#%RELEASE%#$(RELEASE)#g' \
	    < $< > $@

rpm: tar $(SPECFILE)
	rpm -ba $(SPECFILE)


