<?
// $Id: common.inc,v 1.5 2002/08/13 12:20:21 tis Exp $
// common functions used by dns and portal-admin

function connect_ldap()
{
	global $ldap, $binddn, $LDAPHOST, $BINDBASE, $BINDUID, $PHP_AUTH_USER, $PHP_AUTH_PW;
	$binddn = "$BINDUID=$PHP_AUTH_USER,$BINDBASE";
	$ldap = ldap_connect($LDAPHOST);
	if ($ldap) {
		if (!$PHP_AUTH_PW || !@ldap_bind($ldap, $binddn, $PHP_AUTH_PW)) {
			header("WWW-Authenticate: Basic realm=\"Bind to 1 ldap://$LDAPHOST/$binddn\"");
			header("HTTP/1.0 401 Unauthorized");
			exit;
		}
	} else {
		die("Unable to connect to LDAP host: $LDAPHOST");
	}
}

function error_confirm($errmsg)
{
	print "<CENTER><BR><h2><FONT color='red'>$errmsg</FONT></h2><BR>\n";
	log_action("error: ".$errmsg);
}

function log_action($errmsg)
{
	global $LOGFILE, $REMOTE_ADDR, $PHP_AUTH_USER;
	$fd = fopen("$LOGFILE", "a");
	fwrite($fd, "[".date("H:i:s d/M/Y")."] $PHP_AUTH_USER@$REMOTE_ADDR $errmsg\n");
	fclose($fd);
}

# Use this function to determine contraints on objects and returns a set
# of characters with the following meaning:
# o: binddn owns the object
# a: binddn is administrator
# m: binddn is member
function check_constraint($dn = "")
{
	global $ldap, $binddn, $BASEDN;
	$result = "";
	$num_owners = 0;
	if (strlen($dn)>0) {
		// get owners for this object
		$query = ldap_read($ldap, $dn, "(objectclass=*)", array("owner"));
		$entries = ldap_get_entries($ldap, $query);
		ldap_free_result($query);
		$num_owners = $entries[0][owner][count];
		for ($i = 0; $i<$num_owners; $i++) {
			if ($entries[0][owner][$i]==$binddn) {
				$result .= "o";
				$num_owners = 0;
			}
		}
	}
	// get administrators for BASEDN
	$query = ldap_read($ldap, $BASEDN, "(objectclass=*)", array("administrator", "member"));
	$entries = ldap_get_entries($ldap, $query);
	ldap_free_result($query);
	for ($i = 0; $i<$entries[0][administrator][count]; $i++) {
		if ($entries[0][administrator][$i]==$binddn) {
			$result .= "a";
			break;
		}
	}
	if ($num_owners==0) {
		// only objects owned by nobody except binddn are granted to members
		for ($i = 0; $i<$entries[0][member][count]; $i++) {
			if ($entries[0][member][$i]==$binddn) {
				$result .= "m";
				break;
			}
		}
	}
	print "<!-- dn: $dn constraint: $result -->";
	return $result;
}

?>
