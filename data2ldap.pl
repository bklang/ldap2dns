#!/usr/bin/perl
# To use this script, your tinydns data file must define dns zones
# before any records associated with that zone.  For instance, to define the
# alkaloid.net zone the first record found by this script must either be a
# "Z" or "." record so that the tree is created in the proper order.  Not
# following this rule will result in LDAP errors when importing the resulting
# dataset.  To correct such an error just find all zone definitions and import
# those first, then add all records.  This script may be extended to do that
# automatically for you at some point in the future but until that day follow
# this simple procedure and you shouldn't have any problems.
use strict;
use warnings;

my $file = $ARGV[0];
my $output = $ARGV[1];
my $basedn = $ARGV[2];
my $outfh;

if (!defined($file)) {
    print STDERR "Must specify path to 'data' file to read\n";
    exit 1;
}

if (!defined($output) || $file eq '-') {
    $output = "/dev/stdout";
}
open($outfh, ">$output") or die ("Unable to open $output for writing!");

if (!defined($basedn)) {
    print STDERR "Must specify a base DN as the third argument\n";
    exit 1;
}

open(DATA, $file) or die ("Unable to open $file for reading\n");
LINE: while(<DATA>) {
    chomp;
    for ($_) {
        /^\s*#/ && do {
            # Found a comment
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
            if (defined($ip)) {
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
            print $outfh "dnszonename: v-office.biz\n";
            if (defined($master)) { print $outfh "dnszonemaster: $master\n"; }
            if (defined($admin)) { print $outfh "dnsadminmailbox: $admin\n"; }
            if (defined($serial)) { print $outfh "dnsserial: $serial\n"; }
            if (defined($refresh)) { print $outfh "dnsrefresh: $refresh\n"; }
            if (defined($retry)) { print $outfh "dnsretry: $retry\n"; }
            if (defined($expire)) { print $outfh "dnsexpire: $expire\n"; }
            if (defined($minimum)) { print $outfh "dnsminimum: $minimum\n"; }
            if (defined($ttl)) { print $outfh "dnsttl: $ttl\n"; }
            if (defined($timestamp)) { print $outfh "dnstimestamp: $timestamp\n"; }
            if (defined($loc)) { print $outfh "dnslocation: $loc\n"; }
            print $outfh "\n";
        }; # End SOA record

        /^\./ && do {
            # NS+SOA+A Record
            my ($fqdn, $ip, $x, $ttl, $timestamp, $loc) = split /:/;
            $fqdn =~ s/^\.//;

            my $id = "$fqdn-$ip-$x-$ttl-$timestamp-$loc";
            # To find the domain name, the fqdn must have two words of any
            # characters with one period somehere in the middle and an optional
            # trailing period (which is trimmed) just before the end of the line
            $fqdn =~ /.\.*(.+\..+)\.*$/;
print STDERR "$1\n";
            if (!defined($1)) {
                die ("Unable to find domain name for $fqdn!\n");
            }
            my $domain = $1;
            print $outfh "dn: cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "cn: $domain\n";
            print $outfh "dnszonename: v-office.biz\n";
            if (defined($ttl)) { print $outfh "dnsttl: $ttl\n"; }
            if (defined($timestamp)) { print $outfh "dnstimestamp: $timestamp\n"; }
            if (defined($loc)) { print $outfh "dnslocation: $loc\n"; }


            print $outfh "dn: cn=$id,cn=$domain,$basedn\n";
            print $outfh "objectClass: top\n";
            print $outfh "objectClass: dnszone\n";
            print $outfh "objectClass: dnsrrset\n";
            print $outfh "cn: $id\n";
            print $outfh "dnstype: ns\n";
            if (index($x, /\./) > -1) {
                print $outfh "dnsdomainname: $x.\n";
            } else {
                print $outfh "dnsdomainname: $x.ns.$fqdn.\n";
            }
            if (defined($ip)) { print $outfh "dnscipaddr: $ip\n"; }
            print $outfh "\n";
            next LINE;
        };
    } # End for($_) block
} # End LINE while(<DATA>)
