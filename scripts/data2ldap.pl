#!/usr/bin/perl
# $Id$
use strict;
use warnings;
#use POSIX qw(strftime):

my $file = $ARGV[0];
my $output = $ARGV[1];
my $rejout;
my $basedn = $ARGV[2];
my %domains; # Keep track of which domains for which we have
             # already written an SOA
my $outfh;
my $rejfh;
#my $newserial = strftime("%Y%m%d01");

if (!defined($file)) {
    print STDERR "Must specify path to 'data' file to read\n";
    exit 1;
}

if (!defined($output) || $output eq '-') {
    $output = "/dev/stdout";
    $rejout = "/dev/null";
} else {
    $rejout = "$output.rej";
}
open($outfh, ">$output") or die ("Unable to open $output for writing!");
open($rejfh, ">$rejout") or die ("Unable to open $rejout for writing");

if (!defined($basedn)) {
    print STDERR "Must specify a base DN as the third argument\n";
    exit 1;
}


# We run in two iterations.  The first attempts to enumerate all zones
# for which we have records and create SOAs in LDAP.  The reason for this is
# zones are used as a container for all records so they must be in place before
# we start to add any zone data.  While it takes longer, this mechanism ensures
# the proper sequence.
open(DATA, $file) or die ("Unable to open $file for reading\n");
LINE: while(<DATA>) {
    chomp;
    for ($_) {
        /^\s*#/ && do {
            # Found a comment
            next LINE;
        };

        /^-/ && do {
            # Found a disabled A record
            print STDERR "Ignoring disabled record: $_\n";
            print $rejfh "$_\n";
            next LINE;
        };

        /^%/ && do {
            # Location definition: %code:1.2.3.4
            my ($loc, $ip) = split /:/;
            $loc =~ s/^%//;

            print $outfh "dn: dnslocation=$loc,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnsloccodes\n";
            print $outfh "dnslocation: $loc\n";
            if (defined($ip) && $ip) {
                print $outfh "dnsipaddr: $ip\n";
            } else {
                print $outfh "dnsipaddr: :\n";
            }
            print $outfh "\n";

            next LINE;
        }; # End location definition

        /^Z/ && do {
            my ($domain, $master, $admin, $serial, $refresh, $retry, $expire,
                $minimum, $ttl, $timestamp, $loc) = split /:/;
            $domain =~ s/^Z//;

            print $outfh "dn: cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "cn: $domain\n";
            print $outfh "dnszonename: $domain\n";
            print $outfh "dnszonemaster: $master\n";
            print $outfh "dnsadminmailbox: $admin\n";
            if ($serial) { print $outfh "dnsserial: $serial\n"; }
            if ($refresh) { print $outfh "dnsrefresh: $refresh\n"; }
            if ($retry) { print $outfh "dnsretry: $retry\n"; }
            if ($expire) { print $outfh "dnsexpire: $expire\n"; }
            if ($minimum) { print $outfh "dnsminimum: $minimum\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnslocation: $loc\n"; }
            print $outfh "\n";
        }; # End SOA record

        /^\./ && do {
            # NS+SOA+A Record
            my ($fqdn, $ip, $x, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^\.//;

            # To find the domain name, the fqdn must have two words of any
            # characters with one period somehere in the middle and an optional
            # trailing period (which is trimmed) just before the end of the line
            $fqdn =~ /^\.*([A-Za-z0-9-]+\.[A-Za-z0-9-]+)\.*$/;
            if (!defined($1)) {
                die ("Unable to find domain name for $fqdn!\n");
            }
            my $domain = getdomain($fqdn);
            if (defined($domains{$domain})) { 
                # We've already generated an SOA for this domain
                next LINE;
            }
            print $outfh "dn: cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "cn: $domain\n";
            print $outfh "dnszonename: $domain\n";
            print $outfh "dnszonemaster: $x\n";
            print $outfh "dnsadminmailbox: hostmaster.$domain\n";
            if (defined($ttl)) { print $outfh "dnsttl: $ttl\n"; }
            if (defined($timestamp)) { print $outfh "dnstimestamp: $timestamp\n"; }
            if (defined($loc)) { print $outfh "dnslocation: $loc\n"; }
            print $outfh "\n";
            $domains{$domain} = 1;
            next LINE;
        };
    } # End for($_) block
} # End LINE while(<DATA>)

# Done with zone SOAs, being with resource records

seek(DATA, 0, 0) or die ("Unable to seek $file for reading\n");
LINE: while(<DATA>) {
    chomp;
    for ($_) {
        /^\s*#/ && do {
            # Found a comment
            next LINE;
        };

        /^-/ && do {
            # Found a disabled.  User was warned above
            next LINE;
        };

        /^\./ && do {
            # Found NS + A + SOA (SOA handled above)
            my ($fqdn, $ip, $x, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^\.//;
            if (!defined($ip)) { $ip = ""; }
            if (!defined($x)) { $x = ""; }
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "NSA-$fqdn-$ip-$x-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: ns\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            if ($x) { print $outfh "dnscname: $x.\n"; }
            if ($ip) { print $outfh "dnsipaddr: $ip\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^&/ && do {
            # Found NS
            my ($fqdn, $ip, $x, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^&//;
            if (!defined($ip)) { $ip = ""; }
            if (!defined($x)) { $x = ""; }
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "NS-$fqdn-$ip-$x-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: ns\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            if ($ip) { print $outfh "dnsipaddr: $ip\n"; }
            if ($x) { print $outfh "dnscname: $x.\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^=/ && do {
            # Found an A + PTR
            my ($fqdn, $ip, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^=//;
            if (!defined($ip)) { $ip = ""; }
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "APTR-$fqdn-$ip-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: a\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            if ($ip) { print $outfh "dnscipaddr: $ip\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^\+/ && do {
            # Found an A
            my ($fqdn, $ip, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^\+//;
            if (!defined($ip)) { $ip = ""; }
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "A-$fqdn-$ip-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: a\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            if ($ip) { print $outfh "dnsipaddr: $ip\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^@/ && do {
            # Found an MX
            my ($fqdn, $ip, $x, $dist, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^@//;
            if (!defined($ip)) { $ip = ""; }
            if (!defined($x)) { $x = ""; }
            if (!defined($dist)) { $dist = ""; }
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "MX-$fqdn-$ip-$x-$dist-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: mx\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            if ($ip) { print $outfh "dnsipaddr: $ip\n" };
            if ($x) { print $outfh "dnscname: $x.\n"; }
            if ($dist) { print $outfh "dnspreference: $dist\n"; }
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^'/ && do {
            # Currently unsupported
            print STDERR "Ignoring unsupported TXT record: $_\n";
            print $rejfh "$_\n";
            next LINE;
            # Found an MX
            my ($fqdn, $s, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^'//;
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "TXT-$fqdn-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: txt\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            # FIXME Add TXT support to ldap2dns
            # print $outfh "dnstxt: $s\n";
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^\^/ && do {
            # Found an PTR
            my ($fqdn, $ptr, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^\^//;
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "$fqdn-$ptr-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: ptr\n";
            print $outfh "dnscname: $fqdn.\n";
            print $outfh "dnsipaddr: $ptr\n";
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^C/ && do {
            # Found a CNAME
            my ($fqdn, $p, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^C//;
            if (!defined($ttl)) { $ttl = ""; }
            if (!defined($timestamp)) { $timestamp = ""; }
            if (!defined($loc)) { $loc = ""; }
            my $id = "CNAME-$fqdn-$p-$ttl-$timestamp-$loc";
            my $domain = getdomain($fqdn);

            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: cname\n";
            print $outfh "dnsdomainname: $fqdn.\n";
            print $outfh "dnscname: $p.\n";
            if ($ttl) { print $outfh "dnsttl: $ttl\n"; }
            if ($timestamp) { print $outfh "dnstimestamp: $timestamp\n"; }
            if ($loc) { print $outfh "dnsloc: $loc\n"; }
            print $outfh "\n";
            next LINE;
        };

        /^:/ && do {
            # Found unsupported "unknown record"
            print STDERR "Ignoring \"unknown record\": $_\n";
            print $rejfh "$_\n";
            next LINE;
        }
    } # End for($_) block
} # End LINE while(<DATA>)

sub getdomain
{
    my $fqdn = shift(@_);
    $fqdn =~  /\.*([A-Za-z0-9\-]+\.[A-Za-z0-9\-]+)\.*$/;
    return $1;
}
