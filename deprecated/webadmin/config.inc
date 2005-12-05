<?

#################### basic configuration ####################
$LDAPHOST = "ldap.company.com";
$BASEDN = "ou=dns,o=company";
$BINDBASE = "ou=people,o=company";
$BINDUID = "uid";
$ANONBINDDN = "ou=dns,o=company";
$ZONEEDIT = "/dns/index.php";
$LOGFILE = "/var/log/zoneedit_log";


#################### default values ####################
$DEFAULT_TTL = "3600";
$DEFAULT_PREFERENCE = "10";
$DNSADMIN_MAILTO = "hostmaster\@company.com";
$NAMESERVERS = array("ns1.company.com", "ns2.company.com");
$ZONE_INFO = array("dnszonename", "dnsserial", "dnsclass", "dnstype", "dnsexpire", "dnsretry", "dnsminimum",
	"dnszonemaster", "dnsrefresh", "dnsadminmailbox", "dnsttl" );
$ZONE_SOA = array(
	"dnszonename" => "",
	"dnsserial" => "",
	"dnsclass" => "IN",
	"dnstype" => "SOA",
	"dnsexpire" => "604800",
	"dnsretry" => "3600",
	"dnsminimum" => "86400",
	"dnsrefresh" => "10800",
	"dnsttl" => "3600",
	"dnszonemaster" => "ns1.company.com.",
	"dnsadminmailbox" => "hostmaster.company.com.",
);
$ZONE_ENTRY = array(
	array("cn"=>"NS1:", "objectclass"=>"dnsrrset", "dnstype"=>"NS", "dnsclass"=>"IN", "dnsttl"=>"3600", "dnscname"=>"ns1.company.com."),
	array("cn"=>"NS2:", "objectclass"=>"dnsrrset", "dnstype"=>"NS", "dnsclass"=>"IN", "dnsttl"=>"3600", "dnscname"=>"ns2.company.com."),
);

#################### whois configuration ####################
$WHOISSERVERS = array( "at"=>"whois.nic.at", "de"=>"whois.denic.de", "ch"=>"whois.nic.ch",
    "com"=>"whois.networksolutions.com", "net"=>"whois.networksolutions.com",
    "org"=>"whois.networksolutions.com", "be"=>"whois.dns.be", "cz"=>"whois.nic.cz",
    "fr"=>"whois.nic.fr", "hu"=>"whois.nic.hu", "it"=>"whois.nic.it", "dk"=>"whois.dk-hostmaster.dk",
    "li"=>"whois.nic.li", "lu"=>"whois.dns.lu", "cc"=>"whois.nic.cc", "uk"=>"whois.nic.uk" );
?>
