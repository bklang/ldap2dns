#!/usr/sbin/perl
use CGI qw(:standard);
use Net::LDAP;
use strict;
use vars qw($LDAPHOST $BASEDN $BINDBASE $BINDUID $ANONBINDDN $ZONEEDIT $DEFAULT_MAIN @our_nameserver @zoneinfo @setinfo);
my $LDAPHOST = "ldap0.server";
my $BASEDN = "ou=dns,o=tiscover";
my $BINDBASE = "ou=people,o=tiscover";
my $BINDUID = "uid";
my $ANONBINDDN = "ou=dns,o=tiscover";
my $ZONEEDIT = "zoneedit.pl";
my $DEFAULT_MAIN = "index.html";
my $LOGFILE = "/opt/httpd/logs/zoneedit.log";
my @our_nameserver = ( "ns1.tis.co.at", "ns2.tis.co.at" );
my @zoneinfo = qw( DNSzonename DNSserial DNSclass DNStype DNSexpire DNSretry DNSminimum DNSzonemaster DNSrefresh DNSadminmailbox DNSttl );
my @setinfo = qw( DNSdomainname DNStype DNSclass DNScname DNSipaddr DNSttl );


################################################################################

eval {
	main();
};
if ($@) {
	errconfirm($@);
}


sub main
{
	my $request = Apache->request();
	my $query = new CGI;
	my $call = $query->param('call');
	if (defined $call) {
		my $ldap = Net::LDAP->new($LDAPHOST) or die "can't make new LDAP object: $@";
		my $user = $request->connection->user();
		my $binddn = $BINDUID."=".$user.",$BINDBASE";
		my ($ret, $password) = $request->get_basic_auth_pw();
		my $mesg = $ldap->bind($binddn, password => $password);
		die "Unable to bind to LDAP server.<BR>Reason: ".$mesg->error if ($mesg->code);
		my $selet = $query->param('selet') if $query->param('selet');
		if ($call eq "dnslist") {
			dns_list($query, $ldap, $selet);
		} elsif ($call eq "newzone") {
			new_zone($query, $selet);
		} elsif ($call eq "addzone") {
			my $zonedn = add_zone($query, $ldap);
			log_action($user, "add_zone", $zonedn);
			$query->delete_all();
			print $query->header, $query->start_html(-title=> 'Edit DNS Zone',
			    -target=> 'main',
			    -author=> 'jacob.rief@tiscover.com',
			    -BGCOLOR=> 'WHITE'),
			    "<CENTER><BR>";
			edit_zone($query, $ldap, $zonedn, $selet);
			print $query->end_html;
		} elsif ($call eq "editzone") {
			my $zonedn = $query->param('zonedn');
			if (defined $query->param('modifyzone')) {
				modify_zone($query, $ldap, $zonedn);
				log_action($user, "modify_zone_soa", $zonedn);
			} elsif (defined $query->param('addrrset')) {
				add_rrset($query, $ldap, $zonedn);
				log_action($user, "add_rrset", $zonedn);
			} elsif (defined $query->param('modifyrrset')) {
				my $setdn = $query->param('setdn');
				modify_rrset($query, $ldap, $zonedn, $setdn);
				log_action($user, "modify_rrset", $setdn);
			} elsif (defined $query->param('deleterrset')) {
				my $setdn = $query->param('setdn');
				delete_rrset($query, $ldap, $zonedn, $setdn);
				log_action($user, "delete_rrset", $setdn);
			}
			$query->delete_all();
			print $query->header, $query->start_html(-title=> 'Edit DNS Zone',
			    -target=> 'main',
			    -author=> 'jacob.rief@tiscover.com',
			    -BGCOLOR=> 'WHITE'),
			    "<CENTER><BR>";
			print_whois($ldap, $zonedn) if ($request->method eq "GET");
			edit_zone($query, $ldap, $zonedn, $selet);
			print $query->end_html;
		} elsif ($call eq "deletezone") {
			my $zonedn = $query->param('zonedn');
			delete_zone($query, $ldap, $zonedn);
			log_action($user, "delete_zone", $zonedn);
		}
		$ldap->unbind();
	} else {
		# print frame
		print $query->header, 
		    "<FRAMESET COLS=\"250,*\" BORDER=0 FRAMEBORDER=0 FRAMESPACING=0>",
		    "    <FRAME SRC=\"$ZONEEDIT?call=dnslist&nslu=1\" NAME=\"menu\" NORESIZE MARGINWIDTH=0 MARGINHEIGHT=0>",
		    "    <FRAME SRC=\"$DEFAULT_MAIN\" NAME=\"main\" MARGINWIDTH=0 MARGINHEIGHT=0>",
		    "</FRAMESET>";
	}
}


sub errconfirm
{
	my $errmsg = shift;
	my $request = Apache->request();
	$request->note_basic_auth_failure();
	my $query = new CGI;
	print $query->header, $query->start_html(-title=> 'DNS Zone Admin',
	    -target=> 'main',
	    -author=> 'jacob.rief@tiscover.com',
	    -BGCOLOR=> 'WHITE'),
	    "<CENTER><BR>",
	    $query->h2("An error occured"),
	    "<FONT color=red>Message: $errmsg</FONT><BR>\n",
	    $query->end_html;
	$request->child_terminate();
}


sub log_action
{
	my ($user, $action, $dn) = @_;
	my ($sec,$min,$hour,$mday,$mon,$year) = localtime();
	my @month = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	my ($m, $y) = ($month[$mon], $year+1900);
	open(FILE, ">>$LOGFILE");
	print FILE "[$mday/$m/$y:$hour:$min:$sec] $user $action $dn\n";
	close(FILE);
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


sub dns_list
{
	my ($query, $ldap, $selet) = @_;
	my @letters = qw( 0 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z );
	print $query->header, $query->start_html(-title=> 'Zone-Selector',
	    -target=> 'menu',
	    -author=> 'jacob.rief@tiscover.com',
	    -BGCOLOR=> 'WHITE');
	my ($dnslookup, $resolver);
	if ($selet =~ /\~/) {
		$dnslookup = 1;
		use Net::DNS;
		$resolver = new Net::DNS::Resolver;
	} else {
		$dnslookup = 0;
	}
	print "<TABLE BORDER=0 CELLSPACING=1 CELLPADDING=1 COLS=1 BGCOLOR=#BBBBBB>\n",
	      "<TR ALIGN=center><TH><A HREF=\"$ZONEEDIT?call=newzone&selet=$selet\" TARGET=\"main\">Add New Zone</A></TH></TR>\n";
	foreach my $let (@letters) {
		if ($selet =~ /$let/) {
			my $newselet = $selet;
			$newselet =~ s/$let//;
			print "<TR><TD><A HREF=\"$ZONEEDIT?call=dnslist&selet=$newselet\"><B>- $let</B></A></TD></TR>\n";
		} else {
			my $newselet = $selet.$let;
			print "<TR><TD><A HREF=\"$ZONEEDIT?call=dnslist&selet=$newselet\"><B>+ $let</B></A></TD></TR>\n";
			next;
		}
		my $mesg = $ldap->search(base => $BASEDN, filter => "(&(objectclass=DNSzone)(DNSzonename=$let*))");
		my @entries = $mesg->entries;
		my ($zonename, %dn_entry, @unsorted);
		foreach my $entry (@entries) {
			$zonename = $entry->get_value('DNSzonename');
			push @unsorted, $zonename;
			$dn_entry{$zonename} = $entry->dn();
		}
		@entries = sort @unsorted;
		foreach $zonename (@entries) {
			my $zonedn = $dn_entry{$zonename};
			if ($dnslookup) {
				my $query = $resolver->search($zonename, "NS");
				my @ns;
				if ($query) {
					foreach my $rr ($query->answer) {
						next unless $rr->type eq "NS";
						push @ns, $rr->nsdname;
					}
				}
				if (lc($ns[0]) eq lc($our_nameserver[0]) || lc($ns[1]) eq lc($our_nameserver[1]) 
				  || lc($ns[0]) eq lc($our_nameserver[1]) || lc($ns[1]) eq lc($our_nameserver[0]) ) {
					print "<TR ALIGN=center BGCOLOR=#AAFFAA><TD>";
				} elsif (defined $ns[0] || defined $ns[1]) {
					print "<TR ALIGN=center BGCOLOR=#FFAAAA><TD>";
				} else {
					print "<TR ALIGN=center BGCOLOR=#FFFFAA><TD>";
				}
			} else {
				print "<TR ALIGN=center BGCOLOR=#EEEEEE><TD>";
			}
			print "<A HREF=\"$ZONEEDIT?call=editzone&zonedn=$zonedn&selet=$selet\" TARGET=\"main\">$zonename</A></TD></TR>\n";
		}
	}
	print "<TR ALIGN=center><TH><A HREF=\"$ZONEEDIT?call=dnslist";
	if ($dnslookup) {
		$selet =~ s/\~//;
		print "&selet=$selet\" TARGET=\"menu\">Without DNS-lookup</A></TH></TR>\n";
	} else {
		print "&selet=$selet~\" TARGET=\"menu\">With DNS-lookup</A></TH></TR>\n";
	}
	print "</TABLE>\n", $query->end_html;
}


sub print_zone_soa
{
	my $zonedata = shift;
	print "<TR><TD ALIGN=right>Serial: </TD><TD>",
	    textfield(-name=>'DNSserial', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSserial'}),
	    "</TD>", "<TD ALIGN=right>Refresh: </TD><TD>",
	    textfield(-name=>'DNSrefresh', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSrefresh'}),
	    "</TD></TR>\n",

	    "<TR><TD ALIGN=right>Retry: </TD><TD>",
	    textfield(-name=>'DNSretry', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSretry'}),
	    "</TD>", "<TD ALIGN=right>Expire: </TD><TD>",
	    textfield(-name=>'DNSexpire', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSexpire'}),
	    "</TD></TR>\n",

	    "<TR><TD ALIGN=right>Minimum: </TD><TD>",
	    textfield(-name=>'DNSminimum', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSminimum'}),
	    "</TD>", "<TD ALIGN=right>Adminmailbox: </TD><TD>",
	    textfield(-name=>'DNSadminmailbox', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSadminmailbox'}),
	    "</TD></TR>\n",

	    "<TR><TD ALIGN=right>Zonemaster: </TD><TD>",
	    textfield(-name=>'DNSzonemaster', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSzonemaster'}),
	    "</TD>", "<TD ALIGN=right>Time to live: </TD><TD>",
	    textfield(-name=>'DNSttl', -size=>16, -maxlength=>24, -default=>$$zonedata{'DNSttl'}),
	    "</TD><TR>\n";
}


sub new_zone
{
	my ($query, $selet) = @_;
	my %default_zonedata = (
		"DNSzonename" => "",
		"DNSserial" => "",
		"DNSclass" => "IN",
		"DNStype" => "SOA",
		"DNSexpire" => "259200",
		"DNSretry" => "3600",
		"DNSminimum" => "86400",
		"DNSzonemaster" => "ns1.tis.co.at.",
		"DNSrefresh" => "10800",
		"DNSadminmailbox" => "domreg.tis.co.at.",
		"DNSttl" => "3600",
	);
	my ($sec,$min,$hour,$mday,$mon,$year) = localtime();
	$default_zonedata{"DNSserial"} = sprintf "%04d%02d%02d01", $year+1900, $mon+1, $mday;
	my $onsubmit = "{ parent.frames.menu.location='$ZONEEDIT?call=dnslist&selet=$selet'; }";
	$query->param(call=>'addzone');
	print $query->header, $query->start_html(-title=> 'Add DNS Zone',
	    -target=> 'main',
	    -author=> 'jacob.rief@tiscover.com',
	    -BGCOLOR=> 'WHITE'),
	    "<CENTER><BR>",
	    $query->h2('Add DNS zone'),
	    $query->start_multipart_form(-method=>'POST', -action=>"$ZONEEDIT", -target=>'main', -onSubmit=>$onsubmit),
	    $query->hidden('call'), $query->hidden('selet'),
	    "<TABLE BORDER=1 WIDTH=85% COLS=4>\n",
	    "<TR><TD ALIGN=right colspan=2> New Zonename: </TD><TD colspan=2>",
	    $query->textfield(-name=>'DNSzonename', -size=>40, -maxlength=>64),
	    "</TD></TR>\n"; 
	print_zone_soa(\%default_zonedata);
	print "<TR><TD colspan=2 ALIGN=center>",
	    $query->submit(-name=>"  Submit  "),
	    "</TD><TD colspan=2 ALIGN=center>",
	    $query->reset(),
	    "</TD></TR></TABLE>\n",
	    $query->end_form(),
	    $query->end_html;
}


sub add_zone
{
	my ($query, $ldap) = @_;
	my %zonedata;
	foreach my $za (@zoneinfo) {
		$zonedata{$za} = $query->param($za) if defined $query->param($za);
	}
	my ($zonename, $zonedn) = ($zonedata{'DNSzonename'}, "cn=$zonedata{'DNSzonename'},$BASEDN");
	my $attrs = list_attrs(\%zonedata);
	push(@$attrs, "objectclass", "DNSzone", "cn", "$zonename");
	my $mesg = $ldap->add(dn=>$zonedn, attr=>$attrs);
	die "Failed to add zone: $zonename<BR>Reason: ".$mesg->error if ($mesg->code);
	my @attr = ( "cn", "NS1:", "objectclass", "DNSrrset", "dnstype", "NS", "dnsclass", "IN",
	     "dnsttl", "3600", "dnscname", $our_nameserver[0]."." );
	my $dnch = "cn=NS1:,$zonedn";
	die "Failed to add $dnch  " if (($mesg = $ldap->add(dn=>$dnch, attr=>\@attr))->code);

	@attr = ( "cn", "NS2:", "objectclass", "DNSrrset", "dnstype", "NS", "dnsclass", "IN",
	     "dnsttl", "3600", "dnscname", $our_nameserver[1]."." );
	$dnch = "cn=NS2:,$zonedn";
	die "Failed to add $dnch  " if (($mesg = $ldap->add(dn=>$dnch, attr=>\@attr))->code);

	@attr = ( "cn", "A:www", "objectclass", "DNSrrset", "dnstype", "A", "dnsclass", "IN",
	     "dnsdomainname", "www", "dnsttl", "3600", "dnsipaddr", "195.96.23.204" );
	$dnch = "cn=A:www,$zonedn";
	die "Failed to add $dnch<BR>Reason:  ".$mesg->error if (($mesg = $ldap->add(dn=>$dnch, attr=>\@attr))->code);
	return $zonedn;
}


sub modify_zone
{
	my ($query, $ldap, $zonedn) = @_;
	my %zonedata;
	foreach my $za (@zoneinfo) {
		$zonedata{$za} = $query->param($za) if defined $query->param($za);
	}
	my @zonename;
	my $zn = ($ldap->search(base=>$zonedn, scope=>'base', filter=>"(objectclass=DNSzone)")->entry(0))->get_value('DNSzonename');
	push @zonename, $zn;
	for (my $zc = 0; defined $query->param("DNSzonename$zc"); $zc++) {
		$zn = $query->param("DNSzonename$zc");
		push @zonename, $zn if (length($zn)>3);
	}
	my $mesg = $ldap->modify($zonedn, delete => [ 'DNSzonename' ]);
	$mesg = $ldap->modify($zonedn, replace => \%zonedata) unless ($mesg->code);
	$mesg = $ldap->modify($zonedn, add => [ 'DNSzonename' => \@zonename ] ) unless ($mesg->code);
	die "Unable to modify zone: $zonedn<BR>Reason: ".$mesg->error if ($mesg->code);
}


sub delete_zone
{
	my ($query, $ldap, $zonedn) = @_;
	my $zonedn = $query->param('zonedn');
	my $mesg = $ldap->search(base=>$zonedn, filter => "(objectclass=DNSrrset)");
	my @entries = $mesg->entries;
	foreach my $entry (@entries) {
		$mesg = $ldap->delete($entry->dn());
		last if ($mesg->code);
	}
	$mesg = $ldap->delete($zonedn) unless ($mesg->code);
	die "Unable to delete zone $zonedn.<BR>Reason: ".$mesg->error if ($mesg->code);
	dnslist($query, $ldap);
}


sub edit_zone
{
	my ($query, $ldap, $zonedn, $selet) = @_;
	my @zonename = ($ldap->search(base=>$zonedn, scope=>'base', filter=>"(objectclass=DNSzone)")->entry(0))->get_value('DNSzonename');
	my $zonemaster = shift @zonename;
	$query->param(call=>'editzone');
	$query->param(zonedn=>$zonedn);
	$query->param(selet=>$selet);

	# Table for SOA
	print $query->h2("Edit DNS zone <I>$zonemaster</I>");
	print $query->start_multipart_form(-method=>'POST', -action=>"$ZONEEDIT", -target=>'main'),
	    $query->hidden('call'), $query->hidden('zonedn'), $query->hidden('selet'), 
	    "<TABLE BORDER=1 WIDTH=85% COLS=4>\n";
	my $zc = 0;
	my $entry = $ldap->search(base=>$zonedn, scope=>'base', filter=>"(objectclass=DNSzone)")->entry(0);
	my %zonedata;
	foreach my $za (@zoneinfo) {
		$zonedata{$za} = $entry->get_value($za);
	}
	print_zone_soa(\%zonedata);
	print "</TD></TR>\n";
	foreach my $zn (@zonename) {
		print "<TR><TD ALIGN=right colspan=2> Additional Zonename: </TD><TD colspan=2>",
		    $query->textfield(-name=>"DNSzonename$zc", -default=>$zn, -size=>40, -maxlength=>64),
		    "</TD></TR>\n";
		$zc++;
	}
	print "<TR><TD ALIGN=right colspan=2> Add additional Zonename: </TD><TD colspan=2>",
	    $query->textfield(-name=>"DNSzonename$zc", -size=>40, -maxlength=>64),
	    "</TABLE></TD></TR>\n"; 
	print "<TABLE BORDER=1 WIDTH=66% COLS=3><TR><TD align=center>",
	    $query->submit(-name=>"modifyzone", -value=>"  Modify Zone  "), 
	    "</TD><TD align=center>";
	my $onclick = "if(confirm('Do you really want to remove zone \"$zonemaster\" and all its resource records?'))"
	    ."{ parent.frames.menu.location='$ZONEEDIT?call=deletezone&zonedn=$zonedn&selet=$selet'; parent.frames.main.location='$DEFAULT_MAIN'; }";
	print $query->submit(-name=>"deletezone", -value=>"  Delete Zone  ", -onClick=>$onclick),
	    "</TD>\n", $query->end_form(),
	    "<TD align=center>", $query->start_multipart_form(-method=>'POST', -action=>"$ZONEEDIT", -target=>'main'), 
	    $query->hidden('call'), $query->hidden('zonedn'), $query->hidden('selet'),
	    $query->submit(-name=>"resetform", -value=>"  Reset Form  "),
	    $query->end_form(), "</TD></TR></TABLE>\n";

	# Tables for RRsets
	my $mesg = $ldap->search(base=>$zonedn, filter => "(objectclass=DNSrrset)");
	my @entries = $mesg->entries;
	print "\n<TABLE BORDER=1 WIDTH=98% COLS=6 CELLSPACING=0 CELLPADDING=1>\n",
	    "<TR><TH width=20>Name $#entries</TH><TH width=15>Type</TH><TH width=40>IPaddr</TH><TH width=40>CNAME</TH><TH width=20>TTL</TH><TH></TH></TR>\n";
	foreach $entry (@entries) {
		my $setdn = $entry->dn();
		my $domainname = $entry->get_value('DNSdomainname');
		$domainname = "." if (!defined $domainname || length($domainname)<1);
		my $ipaddr = $entry->get_value('DNSipaddr');
		my $cname = $entry->get_value('DNScname');
		my $type = $entry->get_value('DNStype');
		my $ttl = $entry->get_value('DNSttl');
		$query->param(setdn => $setdn);
		print "<TR align=center>", $query->start_multipart_form(-method=>'POST', -action=>"$ZONEEDIT", -target=>'main'), $query->hidden('call'),
		     $query->hidden('selet'), $query->hidden('zonedn'), $query->hidden('setdn'), 
		    "<TD><B>$domainname</B></TD>",
		    "<TD><B>$type</B></TD>",
		    "<TD>", $query->textfield(-name=>'DNSipaddr', -default=>$ipaddr, -size=>16, -maxlength=>16), "</TD>",
		    "<TD>", $query->textfield(-name=>'DNScname', -default=>$cname, -size=>16, -maxlength=>64), "</TD>",
		    "<TD>", $query->textfield(-name=>'DNSttl', -default=>$ttl, -size=>6, -maxlength=>6), "</TD>",
		    "<TD>", $query->submit(-name=>"modifyrrset", -value=>" Modify "), 
		    $query->submit(-name=>"deleterrset", -value=>" Delete "), "</TD>",
		    $query->end_form(), "</TR>\n";
	}
	print "\n<TR align=center>", $query->start_multipart_form(-method=>'POST', -action=>"$ZONEEDIT", -target=>'main'), $query->hidden('call'),
	    $query->hidden('selet'), $query->hidden('zonedn'),
	    "<TD>", textfield(-name=>'DNSdomainname', -size=>8, -maxlength=>32), "</TD>",
	    "<TD>", $query->popup_menu(-name=>'DNStype', -values=>['CNAME','A','MX','NS','PTR','TXT'], -default=>"A"), "</TD>",
	    "<TD>", textfield(-name=>'DNSipaddr', -size=>16, -maxlength=>16), "</TD>",
	    "<TD>", textfield(-name=>'DNScname', -size=>16, -maxlength=>64), "</TD>",
	    "<TD>", textfield(-name=>'DNSttl', -default=>"3600", -size=>6, -maxlength=>6), "</TD>",
	    "<TD>", $query->submit(-name=>"addrrset", -value=>" Add "), "</TD>",
	    $query->end_form();
	print "</TR></TABLE>\n";
}


sub add_rrset
{
	my ($query, $ldap, $zonedn) = @_;
	my ($domainname, $type, @setattrs) = ($query->param('DNSdomainname'), $query->param('DNStype'));
	foreach my $za (@setinfo) {
		next unless (defined $query->param($za));
		push (@setattrs, $za, $query->param($za));
	}
	my $chdn = "$type:$domainname";
	push (@setattrs, "objectclass", "DNSrrset", "cn", "$chdn");
	$chdn = "cn=$chdn,$zonedn";
	my $mesg = $ldap->add($chdn, attr => \@setattrs);
	die "Unable to add rrset: $chdn ".$mesg->error if ($mesg->code);
	my $newserial = $ldap->search(base=>$zonedn, scope=>'base', filter => "(objectclass=DNSzone)")->entry(0)->get_value('DNSserial')+1;
	$mesg = $ldap->modify($zonedn, replace => { 'DNSserial', $newserial });
	die "Unable to modify serial number for: $zonedn ".$mesg->error if ($mesg->code);
}


sub modify_rrset
{
	my ($query, $ldap, $zonedn, $setdn) = @_;
	my %setattrs;
	foreach my $za (@setinfo) {
		next unless (defined $query->param($za));
		$setattrs{$za} = $query->param($za);
	}
	my $mesg = $ldap->modify($setdn, replace => \%setattrs);
	die "Unable to modify rrset: $setdn".$mesg->error if ($mesg->code);
	my $newserial = $ldap->search(base=>$zonedn, scope=>'base', filter => "(objectclass=DNSzone)")->entry(0)->get_value('DNSserial')+1;
	$mesg = $ldap->modify($zonedn, replace => { 'DNSserial', $newserial });
	die "Unable to modify serial number for: $zonedn ".$mesg->error if ($mesg->code);
}


sub delete_rrset
{
	my ($query, $ldap, $zonedn, $setdn) = @_;
	my $mesg = $ldap->delete($setdn);
	die "Unable to modify rrset: $setdn".$mesg->error if ($mesg->code);
	my $newserial = $ldap->search(base=>$zonedn, scope=>'base', filter => "(objectclass=DNSzone)")->entry(0)->get_value('DNSserial')+1;
	$mesg = $ldap->modify($zonedn, replace => { 'DNSserial', $newserial });
	die "Unable to modify serial number for: $zonedn ".$mesg->error if ($mesg->code);
}


sub print_whois
{
	my ($ldap, $zonedn) = @_;
	my ($zonename, $whois) = ($ldap->search(base=>$zonedn, scope=>'base', filter=>"(objectclass=DNSzone)")->entry(0))->get_value('DNSzonename');
	use Net::Whois;
	unless ($whois = new Net::Whois::Domain $zonename) {
		print "<H4>Unable to contact Whois-server</H4>";
		return;
	};
	unless ($whois->ok) {
		print "<H4>No Whois-record found for zone <I>$zonename</I> trying with ";
		# try with parent zone
		if ($zonename =~ /[^.]+\.(.*)/) {
			$zonename = $1;
		}
		print "<I>$zonename</I></H4>\n";
		$whois = new Net::Whois::Domain($zonename);
		return unless ($whois->ok);
	}
	print "<H3>Whois record for zone <I>$zonename</I></H3>\n";
	print "Domain: ", $whois->domain, "<BR>\n";
	print "Name: ", $whois->name, "<BR>\n";
	print "Tag: ", $whois->tag, "<BR>\n";
	print "Address:\n", map { "    $_<BR>\n" } $whois->address;
	print "Country: ", $whois->country, "<BR>\n";
	print "Name Servers:<BR>\n", map { "    $$_[0] ($$_[1])<BR>\n" } @{$whois->servers};
	print "Record created:", $whois->record_created, "<BR>\n";
	print "Record updated:", $whois->record_updated, "<BR>\n" ;
}

