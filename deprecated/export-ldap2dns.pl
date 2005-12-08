#!/usr/bin/perl
# Script to import data from DNS into LDAP
# Copyright 2000, Jacob Rief
# $Id: export-ldap2dns.pl,v 1.1 2002/09/03 10:43:40 jrief Exp $

###### configure this ######
# remember to allow zone transfers from Your nameserver
my $LDAPHOST = "localhost";
my $LDAPBINDDN = "uid=root,o=tiscover";
my $LDAPPASSWD = "XXXXXXX";
my $BASEDN = "ou=dns,o=tiscover";

###### don't edit below this line ######
use strict;
use Net::LDAP qw(LDAP_NO_SUCH_OBJECT LDAP_ALREADY_EXISTS);

my $ldap;
initialize();
migrate_zones();

sub initialize
{
	$ldap = Net::LDAP->new($LDAPHOST) or die "Can't connect to LDAP server";
	my $mesg = $ldap->bind( dn => $LDAPBINDDN, password => $LDAPPASSWD );
	die "Unable to bind to LDAP ", $mesg->error if ($mesg->code);
}

sub migrate_zones
{
	my $mesg = $ldap->search(base=>$BASEDN, scope=>'sub', filter=>"(objectclass=dnszone)");
	my @oldzones = $mesg->entries();
	foreach my $oldzone (@oldzones) {
		my @zonename = $oldzone->get_value('dnszonename');
		my $masterdn = dn_domain($zonename[0]) if ($#zonename>=0);
		foreach my $zn (@zonename) {
			my $newdn = dn_domain($zn);
			next unless ($newdn =~ /^dc=\s*([^,]+).*/);
			my $dc = $1;
			my $soarecord = $oldzone->get_value('dnsserial')." "
			    .$oldzone->get_value('dnsrefresh')." "
			    .$oldzone->get_value('dnsretry')." "
			    .$oldzone->get_value('dnsexpire')." "
			    .$oldzone->get_value('dnsminimum');
			my %attrs = ( 'objectclass' => [ qw(dNSDomain dcObject) ], 'dc' => $dc, 'sOARecord' => [ $soarecord ] );
			$mesg = $ldap->modify($newdn, 'replace' => \%attrs);
			while ($mesg->code()==LDAP_NO_SUCH_OBJECT) {
			    repeat:
				$mesg = $ldap->add($newdn, 'attrs' => list_attrs(\%attrs));
				last unless ($mesg->code()==LDAP_NO_SUCH_OBJECT);
				my $filldn = $newdn;
				do {
					die("Invalid dn: $filldn") unless ($filldn =~ /[^,]+,((dc=[^,]+),.+)/);
					$filldn = $1;
					$mesg = $ldap->add($filldn, 'attrs' => [ 'objectclass'=>'dcObject', 'dc'=>$2) ]);
				} until ($mesg->code()==0 || $mesg->code()==LDAP_ALREADY_EXISTS);
				goto repeat;
			}
			die("Error from LDAP: \"".$mesg->error()."\" on $newdn (".$mesg->code().")") if ($mesg->code());
			if ($masterdn ne $newdn) {
				$mesg = $ldap->modify($masterdn, 'replace' => [ 'objectclass' => 'alias' ]);
				$mesg = $ldap->modify($masterdn, 'add' => [ 'alias' => $newdn ]);
				$mesg = $ldap->modify($newdn, 'replace' => [ 'objectclass' => 'alias', 'alias' => $masterdn ]);
			}
			migrate_rrrecords($zn, $newdn, $oldzone->dn());
		}
	}
}

sub migrate_rrrecords
{
	my ($zonename, $newzonedn, $oldzonedn) = (@_);
	my @objectclass = qw(dNSDomain dcObject);
	my $mesg = $ldap->search(base=>$oldzonedn, scope=>'sub', filter=>"(objectclass=dnsrrset)");
	my @rrsets = $mesg->entries();
	foreach my $rr (@rrsets) {
		my $domainname = $rr->get_value('dnsdomainname');
		my $dn = dn_domain(length($domainname)>0 ? "$domainname.$zonename" : "$zonename");
		my $type = $rr->get_value('dnstype');
		print "dn: $dn (type: $type)\n";
		next unless ($dn =~ /^dc=\s*([^,]+).*/);
		my %attrs = read_ldapobject($dn);
		$attrs{'objectclass'} = \@objectclass;
		$attrs{'dc'} = $1;
		my @cname = $rr->get_value('dnscname');
		my @ipaddr = $rr->get_value('dnsipaddr');
		my $cipaddr = $rr->get_value('dnscipaddr');
		if ($type eq "A") {
			push(@ipaddr, $cipaddr) if (length($cipaddr)>5);
			my $ta = $attrs{'aRecord'};
			push(@$ta, @ipaddr) if ($#ipaddr>=0);
		} elsif ($type eq "NS") {
			my $ta = $attrs{'NSRecord'};
			foreach my $cn (@cname) {
				if ($cn =~ /\.$/) {
					push(@$ta, $cn);
				} else {
					push(@$ta, "$cn.$zonename");
				}
			}
		} elsif ($type eq "MX") {
			my $ta = $attrs{'MXRecord'};
			my $pref = $rr->get_value('dnspreference');
			foreach my $cn (@cname) {
				if ($cn =~ /\.$/) {
					push(@$ta, "$pref $cn");
				} else {
					push(@$ta, "$pref $cn.$zonename");
				}
			}
		} elsif ($type eq "CNAME") {
			my $ta = $attrs{'cNAMERecord'};
			die("no CNAME") unless($#cname>=0);
			foreach my $cn (@cname) {
				if ($cn =~ /\.$/) {
					push(@$ta, $cn);
				} else {
					push(@$ta, "$cn.$zonename");
				}
			}
		}
		remove_unused(\%attrs);
		$mesg = $ldap->modify($dn, 'replace' => \%attrs);
		while ($mesg->code()==LDAP_NO_SUCH_OBJECT) {
		    repeat:
			$mesg = $ldap->add($dn, 'attrs' => list_attrs(\%attrs));
			last unless ($mesg->code()==LDAP_NO_SUCH_OBJECT);
			my $filldn = $dn;
			do {
				die("Invalid dn: $filldn") unless ($filldn =~ /[^,]+,((dc=[^,]+),.+)/);
				$filldn = $1;
				$mesg = $ldap->add($filldn, 'attrs' => [ qw(objectclass dcObject dc $2) ]);
			} until ($mesg->code()==0 || $mesg->code()==LDAP_ALREADY_EXISTS);
			goto repeat;
		}
		die("Error from LDAP: \"".$mesg->error()."\" on $dn") if ($mesg->code());
	}
}

sub dn_domain
{
	my ($domain)=(@_);
	my @p = split /\./, lc($domain);
	my $dc = 'dc='.join(',dc=', @p);
	$dc .= ','.$BASEDN;
	return $dc;
}

sub list_attrs
{
        my $attr = shift;
        my (@list, $key, $value);
        while (($key, $value) = each %$attr) {
                push(@list, $key => $value);
        }
        return \@list;
}

sub read_ldapobject
{
	my $dn = shift;
	my %attrs = ();
	$attrs{'aRecord'} = [];
	$attrs{'cNAMERecord'} = [];
	$attrs{'MXRecord'} = [];
	$attrs{'NSRecord'} = [];
	my $mesg = $ldap->search(base => $dn, scope => 'base', filter => "(objectclass=dcObject)");
	return %attrs if ($mesg->code()==LDAP_NO_SUCH_OBJECT);
	return %attrs if ($mesg->count()==0);
	my $obj = $mesg->entry(0);
	my @tempa = $obj->get_value('aRecord');
	$attrs{'aRecord'} = \@tempa if ($#tempa>=0);
	my @tempcname = $obj->get_value('cNAMERecord');
	$attrs{'cNAMERecord'} = \@tempcname if ($#tempcname>=0);
	my @tempmx = $obj->get_value('MXRecord');
	$attrs{'MXRecord'} = \@tempmx if ($#tempmx>=0);
	my @tempns = $obj->get_value('NSRecord');
	$attrs{'NSRecord'} = \@tempns if ($#tempns>=0);
	return %attrs;
}

sub remove_unused
{
	my $hash = shift;
	foreach my $key (keys %$hash) {
		my $ta = $$hash{$key};
		next if ($key eq "dc");
		delete $$hash{$key} if ($#$ta<0);
	}
}

