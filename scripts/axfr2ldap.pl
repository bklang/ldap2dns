#!/usr/bin/perl
# Script to import data from DNS into LDAP
# Copyright 2000, Jacob Rief

###### configure this ######
# remember to allow zone transfers from Your nameserver
$LDAPHOST = "ldap.myorg.com";
$LDAPBINDDN = "ou=dns,o=myorg";
$LDAPPASSWD = "secret";
$NAMESERVER = "ns1.myorg.com";
$BASEDN = "ou=dns,o=myorg";
$FULL_QUALIFIED_NAME = 0;

###### don't edit below this line ######
use Net::DNS;
use Net::LDAP;

#$ldap = Net::LDAP->new($LDAPHOST) or die "Can't connect to LDAP server";
#$mesg = $ldap->bind( dn => $LDAPBINDDN, password => $LDAPPASSWD );
#die "Unable to bind to LDAP ", $mesg->error if ($mesg->code);

@domains;
while (<>) {
	chomp;
	$_ = lc;
	if (/primary\s+([0-9A-Za-z._+-]+)\s+/) {
		push(@domains, $1);
	}
}
if ($#domains>=0) {
	@domains = sort(@domains);
	for ($i = 1; $i<=$#domains; $i++) {
		if ($domains[$i-1] eq $domains[$i]) {
			print "Warning: removing double entry for zone: $domains[$i]\n";
			splice(@domains, $i, 1);
		}
	}
	print "Adding ". ($#domains+1) ." zones to LDAP server\n";
	foreach(@domains) {
		read_zone($_);
	}
} else {
	print "No domain added to LDAP server\n";
}


sub add_attrs
{
	my ($attr, $zonename) = @_;

	# correct DNScname
	if (defined $$attr{'DNScname'}) {
		# check if DNScname is a real name
		if ($$attr{'DNScname'} =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
			$$attr{'DNSipaddr'} = "$1.$2.$3.$4";
			undef $$attr{'DNScname'};
		}
	}

	my ($tail);
	if ($$attr{'DNSdomainname'} eq $zonename) {
		$tail = "";
	} else {
		split /\.$zonename/, $$attr{'DNSdomainname'};
		die "Corrupt DNSdomainname" unless (defined @_[0]);
		$tail = @_[0];
	}

	if ($FULL_QUALIFIED_NAME) {
		$$attr{'DNSdomainname'} = "$zonename." if ($tail eq "");
		$$attr{'DNSdomainname'} = "$tail.$zonename." unless ($tail eq "");
		$$attr{'DNScname'} .= "." if (defined $$attr{'DNScname'});
	} else {
		$$attr{'DNSdomainname'} = "$tail";
		if (defined $$attr{'DNScname'}) {
			split /\.$zonename/, $$attr{'DNScname'};
			$$attr{'DNScname'} = @_[0] if (defined @_[0]);
		}
	}

	my $rrdn;
	if ($$attr{'DNStype'} eq "A") {
		# A records are multivalued, use one rrset for all ipaddresses
		$$attr{'cn'} = "A:$tail";
		$rrdn = "cn=$$attr{'cn'},cn=$zonename,$BASEDN";
		#$mesg = $ldap->search(base=>$rrdn, scope=>"base", filter => "(objectclass=DNSrrset)");
	} else {
		# All other records are siglevalued, use one rrset for each entry
#		my $i = 0;
#		do {
#			$i++;
			$$attr{'cn'} = "$$attr{'DNStype'}:$tail";
			$rrdn = "cn=$$attr{'cn'},cn=$zonename,$BASEDN";

#			$mesg = $ldap->search(base=>$rrdn, scope=>"base", filter=>"(objectclass=DNSrrset)");
#		} while ($mesg->count>0);
		if ($FULL_QUALIFIED_NAME) {
			$$attr{'DNScname'} = "$$attr{'DNStype'}$i.$zonename." unless defined $$attr{'DNScname'};
		} else {
			$$attr{'DNScname'} = "$$attr{'DNStype'}$i" unless defined $$attr{'DNScname'};
		}
#		$mesg = $ldap->add(dn=>$rrdn, attr=>list_attrs($attr));
#		die "Failed to add entry:", $rrdn, "   ", $mesg->error if ($mesg->code);
	}
	print "dn: $rrdn\n";
	print "$_: $attr{$_}\n" for keys %attr;
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


sub read_zone
{
	my $zonename = shift;

	#~ $res = new Net::DNS::Resolver;
	#~ $res->nameservers($NAMESERVER);
	#~ @zone = $res->axfr($zonename);
	@zone = <"db.$zonename">;
	while (!@zone) {
		#print "Query failed for $zonename: ", $res->errorstring, ".\n";
		#if ($res->errorstring eq "couldn't connect") {
			#print "Trying to reconnect\n";
			#sleep(10);
			#@zone = $res->axfr($zonename);
		#} else {
			#return;
		#}
		print "Could not open zone file for $zonename.\n";
		return
	}
	print "---------- reading zone $zonename ----------\n";
	foreach $rr (@zone) {
		$rr->print;
		if ($rr->type eq "SOA") {
			die "Invalid SOA record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9a-zA-Z_.+-]+)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+([0-9a-zA-Z_.+-]+)\s+([0-9a-zA-Z_.+-]+)\s+\((.*)\)/s);
			die "Corrupt SOA record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type);

			my %attr;
			$attr{'objectclass'} = "DNSzone";
			$attr{'DNSzonename'} = lc $1;
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			$attr{'DNSzonemaster'} = lc $5;
			$attr{'DNSadminmailbox'} = lc $6;
			my $soa = $7;
			die "Invalid SOA fields for ", $zonename, "  " unless ($soa =~ /\s*(\d+)\D*(\d+)\D*(\d+)\D*(\d+)\D*(\d+)\s*/s);
			$attr{'DNSserial'} = $1;
			$attr{'DNSrefresh'} = $2;
			$attr{'DNSretry'} = $3;
			$attr{'DNSexpire'} = $4;
			$attr{'DNSminimum'} = $5;
			$attr{'cn'} = $zonename;
			
		print "dn: cn=$zonename,$BASEDN\n";
		print "$_: $attr{$_}\n" for keys %attr;
#			$mesg = $ldap->add(dn=>"cn=$zonename,$BASEDN", attr=>list_attrs(\%attr));
#			die "Failed to add entry:", $zonename, "   ", $mesg->error if ($mesg->code);
		} elsif ($rr->type eq "A") {
			die "Invalid A record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9a-zA-Z_.+-]+)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+([0-9.]+)/);
			die "Corrupt A record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type && $5 eq $rr->address);

			next if $1 eq "localhost.$zonename";
			my %attr;
			$attr{'objectclass'} = "DNSrrset";
			$attr{'DNSdomainname'} = lc $1;
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			$attr{'DNSipaddr'} = $5;
			add_attrs(\%attr, $zonename);
		} elsif ($rr->type eq "MX") {
			die "Invalid MX record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9a-zA-Z_.+-]+)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+(\d+)\s+([0-9a-zA-Z_.+-]+)/);
			die "Corrupt MX record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type);

			my %attr;
			$attr{'objectclass'} = "DNSrrset";
			$attr{'DNSdomainname'} = lc $1;
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			$attr{'DNSpreference'} = $5;
			$attr{'DNScname'} = lc $6;
			add_attrs(\%attr, $zonename);
		} elsif ($rr->type eq "NS") {
			die "Invalid NS record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9a-zA-Z_.+-]+)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+([0-9a-zA-Z_.+-]+)/);
			die "Corrupt NS record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type);

			my %attr;
			$attr{'objectclass'} = "DNSrrset";
			$attr{'DNSdomainname'} = lc $1;
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			$attr{'DNScname'} = lc $5;
			add_attrs(\%attr, $zonename);
		} elsif ($rr->type eq "CNAME" || $rr->type eq "TXT") {
			die "Invalid ", $rr->type, " record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9a-zA-Z_.+-]+)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+([0-9a-zA-Z_.+-\s\"=:]+)/); 
			die "Corrupt ", $rr->type, " record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type);

			my %attr;
			$attr{'objectclass'} = "DNSrrset";
			$attr{'DNSdomainname'} = $1;
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			if ($rr->type eq "CNAME") {
				$attr{'DNScname'} = $5;
			} elsif ($rr->type eq "TXT") {
				$attr{'DNStxt'} = $5;
			}
			add_attrs(\%attr, $zonename);
		} elsif ($rr->type eq "PTR") {
			die "Invalid PTR record for ", $rr->name, "  " unless ($rr->string =~ /^([0-9.]+\.in-addr\.arpa)\.\s+(\d+)\s+(\w+)\s+(\w+)\s+([0-9a-zA-Z_.+-]+)/);
			die "Corrupt PTR record for ", $rr->name, "  " unless ($1 eq $rr->name && $2 eq $rr->ttl && $3 eq $rr->class && $4 eq $rr->type);

			my %attr;
			$attr{'objectclass'} = "DNSrrset";
			$attr{'DNSdomainname'} = "$1.";
			$attr{'DNSttl'} = $2;
			$attr{'DNSclass'} = $3;
			$attr{'DNStype'} = $4;
			$attr{'DNScname'} = $5;
			if ($attr{'DNSdomainname'} =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
				$attr{'DNSipaddr'} = "$4.$3.$2.$1";
				$attr{'cn'} = "PTR:$1"; # Only for C-level domains yet
			} else { die "Corrupt IP address for", $rr->name; }
			my $rrdn = "cn=$attr{'cn'},cn=$zonename,$BASEDN";
			#$mesg = $add(dn=>$rrdn, attr=>list_attrs(\%attr));
			#die "Failed to add entry:", $rrdn, "   ", $mesg->error if ($mesg->code);
			print "dn: $rrdn\n";
			print "$_: $attr{$_}\n" for keys %attr;
		}
	}
}

