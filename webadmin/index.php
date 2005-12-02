<?
// $Id: index.php,v 1.11 2002/08/13 12:20:22 tis Exp $

include("config.inc");
include("common.inc");
error_reporting(E_ERROR|E_WARNING|E_PARSE);

if (isset($HTTP_GET_VARS[call])) {
	main($HTTP_GET_VARS[call]);
} elseif (isset($HTTP_POST_VARS[call])) {
	main($HTTP_POST_VARS[call]);
} else {
	include("framesets.inc");
}

function main($call)
{
	global $ZONEEDIT, $HTTP_GET_VARS, $HTTP_POST_VARS;
	switch ($call) {
	    case "dnslist":
		connect_ldap();
		include("menuheader.inc");
		if (ereg("[am]", check_constraint())) {
			full_dns_list();
		} else {
			individual_dns_list();
		}
		include("footer.inc");
		break;
	    case "search":
		connect_ldap();
		include("mainheader.inc");
		if (isset($HTTP_GET_VARS[zonename])) {
			$zonedn = search_zone($HTTP_GET_VARS[zonename]);
			if (strlen($zonedn)>0) {
				zone_edit_plus($zonedn);
			} else {
				new_zone($HTTP_GET_VARS[zonename]);
			}
		}	
		include("footer.inc");
		break;
	    case "editzone":
		connect_ldap();
		include("mainheader.inc");
		if (isset($HTTP_POST_VARS[modifysoa])) {
			modify_zone_soa($HTTP_POST_VARS[zonedn]);
			log_action("modify_zone_soa: $HTTP_POST_VARS[zonedn]");
		} elseif (isset($HTTP_POST_VARS[addrrset])) {
			add_rrset($HTTP_POST_VARS[zonedn]);
			log_action("add_rrset: $HTTP_POST_VARS[zonedn]");
		} elseif (isset($HTTP_POST_VARS[modifyrrset])) {
			if (isset($HTTP_POST_VARS[deleterrset])) {
				delete_rrset($HTTP_POST_VARS[zonedn], $HTTP_POST_VARS[setdn]);
				log_action("delete_rrset: $HTTP_POST_VARS[setdn]");
			} else {
				modify_rrset($HTTP_POST_VARS[zonedn], $HTTP_POST_VARS[setdn]);
				log_action("modify_rrset: ".$HTTP_POST_VARS[setdn]);
			}
		}
		if (isset($HTTP_GET_VARS[zonedn]))
			zone_edit_plus($HTTP_GET_VARS[zonedn]);
		elseif (isset($HTTP_POST_VARS[zonedn]))
			edit_zone_attrs($HTTP_POST_VARS[zonedn]);
		include("footer.inc");
		break;
	    case "newzone":
		connect_ldap();
		include("mainheader.inc");
		new_zone();
		include("footer.inc");
		break;
	    case "addzone":
		connect_ldap();
		include("mainheader.inc");
		zone_edit_plus(add_zone());
		include("footer.inc");
		break;
	    case "removezone":
		connect_ldap();
		if (isset($HTTP_GET_VARS[zonedn]) && remove_zone($HTTP_GET_VARS[zonedn])) {
			include("xearthheader.inc");
			include("footer.inc");
		}
		break;
	}
}


function full_dns_list()
{
	global $ldap, $BASEDN, $ZONEEDIT, $HTTP_GET_VARS;
	$letters = array( "0-9","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q-R","S","T","U","V","W","X-Z" );
	if (isset($HTTP_GET_VARS[wait])) sleep($HTTP_GET_VARS[wait]);
	if (isset($HTTP_GET_VARS[selet])) $selet = $HTTP_GET_VARS[selet];
?>
<form method="GET" action="<? echo $ZONEEDIT ?>" target="main" enctype="multipart/form-data">
<input type="hidden" name="call" value="search"><input type="hidden" name="selet" value="<? echo $selet ?>">
&nbsp;Find&nbsp;<input type="text" name="zonename" size="20" maxlength="64">
&nbsp;<input type="submit" name="Go" value="Go">
</form>
<a href="<? echo "$ZONEEDIT?call=newzone&selet=$selet" ?>" TARGET="main">
<img src="icons/zone_new.gif" width="16" height="16" align="texttop" border="0">&nbsp;&nbsp;Add new Zone</a><br>
<?
	foreach ($letters as $let) {
		$tree1 = ($let==$letters[count($letters)-1] ? "end" : "cont");
		if (ereg("(.*)[$let]-[$let](.*)", $selet, $regs)
		    || ereg("(.*)[$let](.*)", $selet, $regs)) {
			$newselet = $regs[1].$regs[2];
			ereg_replace("[$let]+", "", $newselet);
			print "<a href='$ZONEEDIT?call=dnslist&selet=$newselet'>".
			    "<img src='icons/minus-$tree1.gif' width='19' height='16' align='texttop' border='0'>".
			    "<img src='icons/folder-open.gif' width='16' height='16' align='texttop' border='0'>...$let</a><br>\n";
		} else {
			$newselet = $selet.$let;
			print "<a href='$ZONEEDIT?call=dnslist&selet=$newselet'>".
			    "<img src='icons/plus-$tree1.gif' width='19' height='16' align='texttop' border='0'>".
			    "<img src='icons/folder-closed.gif' width='16' height='16' align='texttop' border='0'>...$let</a><br>\n";
			continue;
		}
		$filter = "(&(objectclass=dnszone)";
		if (ereg("([0-9A-Z])-([0-9A-Z])", $let, $regs)) {
			$filter .= "(|";
			for ($i = ord($regs[1]); $i<=ord($regs[2]); $i++) {
				$filter .= "(cn=".chr($i)."*)";
			}
			$filter .= "))";
		} else {
			$filter .= "(cn=$let*))";
		}
		$query = ldap_search($ldap, $BASEDN, $filter);
		//ldap_sort($ldap, $query, "cn");
		$entries = ldap_get_entries($ldap, $query);
		ldap_free_result($query);
		for ($i = 0; $i<$entries[count]; $i++) {
			$zonedn = $entries[$i]["dn"];
			$zonename = $entries[$i]["dnszonename"][0];
			$tree2 = ($i==$entries[count]-1 ? "end" : "cont");
			print "<a href='$ZONEEDIT?call=editzone&zonedn=$zonedn&selet=$selet' TARGET='main'>".
			    "<img src='".($tree1=="cont" ? "icons/img-vert-line.gif" : "icons/img-blank.gif" )."'".
			    " width='19' height='16' align='texttop' border='0'>".
			    "<img src='icons/branch-$tree2.gif' width='19' height='16' align='texttop' border='0'><img src='";
			if (ereg("[d]", $selet)) {
				$auth = authorized($zonename);
				if ($auth==1) {
					print "icons/zone_val.gif";
				} elseif ($auth==-1) {
					print "icons/zone_forb.gif";
				} else {
					print "icons/zone_unre.gif";
				}
			} else {
				print "icons/zone_unkn.gif";
			}
			print "' width='16' height='16' align='texttop' border='0'>&nbsp;$zonename</a><br>\n";
		}
		print "\n";
	}
	#print "<tr align=center><th><a href='$ZONEEDIT?call=dnslist'";
	if (ereg("[d]", $selet)) {
		ereg_replace("[d]", "", $selet);
		print "<a href='$ZONEEDIT?call=dnslist&selet=$selet' TARGET='menu'>Without DNS-lookup</a><br>\n";
	} else {
		print "<a href='$ZONEEDIT?call=dnslist&selet=$selet"."d' TARGET='menu'>With DNS-lookup</a><br>\n";
	}
}

function individual_dns_list()
{
	global $ldap, $binddn, $BASEDN, $ZONEEDIT, $HTTP_GET_VARS;
	$query = ldap_search($ldap, $BASEDN, "(&(objectclass=DNSzone)(owner=$binddn))");
	$entries = ldap_get_entries($ldap, $query);
	for ($i = 0; $i<$entries[count]; $i++) {
		$zonedn = $entries[$i][dn];
		$zonename = $entries[$i][dnszonename][0];
		$tree = ($i==$entries[count]-1 ? "end" : "cont");
		print "<a href='$ZONEEDIT?call=editzone&zonedn=$zonedn' TARGET='main'>".
		    "<img src='icons/branch-$tree.gif' width='19' height='16' align='texttop' border='0'>".
		    "<img src='icons/zone_unkn.gif' width='16' height='16' align='texttop' border='0'>&nbsp;$zonename</a><br>\n";
	}
}

function search_zone($zonename)
{
	global $ldap, $BASEDN;
	$filter = "(&(objectclass=dnszone)(dnszonename=$zonename))";
	$query = ldap_search($ldap, $BASEDN, $filter);
	$entries = ldap_get_entries($ldap, $query);
	if ($entries[count]>1) {
		$mesg = "Ambigous zonenames $zonename in<br>";
		for ($i = 0; $i<$entries[count]; $i++) {
			$mesg .= "dn: <a href='$ZONEEDIT?call=editzone&zonedn=".$entries[$i]["dn"]."' target='main'>".
			    $entries[$i]["dn"]."</a><br>";
		}
		print "<br><h3 align='center'><font color='orange'>Warning: $mesg</font></h3>";
		exit;
	}
	if ($entries[count]==1) {
		return $entries[0][dn];
	} else switch (authorized($zonename)) {
	    case -2:
		error_confirm("The zone does not belong to a valid top level domain");
		exit;
	    case -1:
		error_confirm("The zone is owned by someone else");
		print_whois($zonename);
		exit;
	    default:
		return;
	}
}

function print_zone_soa($zonedata, $constr)
{
	print "<tr><td align='right'>Serial: </td>";
	if (ereg("[amo]", $constr)) {
		print "<td><input type='text' name='dnsserial' size='16' maxlength='24' value='$zonedata[dnsserial]'></td>";
	} else {
		print "<td><b> ".$zonedata["dnsserial"]." </b></td>";
	}
	print "<td align='right'>Refresh: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsrefresh' size='16' maxlength='24' value='$zonedata[dnsrefresh]'>";
	} else {
		print " <b> ".$zonedata["dnsrefresh"]." </b>";
	}
	print "</td></tr>\n<tr><td align='right'>Retry: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsretry' size='16' maxlength='24' value='$zonedata[dnsretry]'>";
	} else {
		print " <b> ".$zonedata["dnsretry"]." </b>";
	}
	print "</td>\n<td align='right'>Expire: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsexpire' size='16' maxlength='24' value='$zonedata[dnsexpire]'>";
	} else {
		print " <b> ".$zonedata["dnsexpire"]." </b>";
	}
	print "</td></tr>\n<tr><td align='right'>Minimum: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsminimum' size='16' maxlength='24' value='$zonedata[dnsminimum]'>";
	} else {
		print " <b> ".$zonedata["dnsminimum"]." </b>";
	}
	print "</td>\n<td align='right'>Adminmailbox: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsadminmailbox' size='16' maxlength='24' value='$zonedata[dnsadminmailbox]'>";
	} else {
		print " <b> ".$zonedata["dnsadminmailbox"]." </b>";
	}
	print "</td></tr>\n<tr><td align='right'>Zonemaster: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnszonemaster' size='16' maxlength='24' value='$zonedata[dnszonemaster]'>";
	} else {
		print " <b> ".$zonedata["dnszonemaster"]." </b>";
	}
	print "</td>\n<td align='right'>Time to live: </td><td>";
	if (ereg("[amo]", $constr)) {
		print "<input type='text' name='dnsttl' size='16' maxlength='24' value='$zonedata[dnsttl]'>";
	} else {
		print " <b> ".$zonedata["dnsttl"]." </b>";
	}
	print "</td></tr>\n";
}

function get_zone_name($zonedn)
{
	global $ldap;
	$query = ldap_read($ldap, $zonedn, "(objectclass=dnszone)", array("dnszonename"));
	$entries = ldap_get_entries($ldap, $query);
	$zonename = $entries[0][dnszonename][0];
	ldap_free_result($query);
	return $zonename;
}

function modify_zone_soa($zonedn)
{
	global $ldap, $ZONE_INFO, $HTTP_POST_VARS;
	$zonename = get_zone_name($zonedn);
	$entry = array();
	foreach ($ZONE_INFO as $za) {
		if (strlen($HTTP_POST_VARS["$za"])>0)
			$entry["$za"] = $HTTP_POST_VARS["$za"];
	}
	if (ereg("[a]", check_constraint($zonedn))) {
		$entry[dnszonename] = array("$zonename");
		for ($i = 0; isset($HTTP_POST_VARS["dnszonename$i"]); $i++) {
			if (strlen($HTTP_POST_VARS["dnszonename$i"])>3)
				array_push($entry[dnszonename], $HTTP_POST_VARS["dnszonename$i"]);
		}
	}
	ldap_modify($ldap, $zonedn, $entry) or die("ldap_modify failed to update SOA for $zonedn");
}

function authorized($zonename)
{
	return 1;
}

function zone_edit_plus($zonedn)
{
	$zonename = get_zone_name($zonedn);
	$auth = authorized($zonename);
	if ($auth==1) {
		print "<center><br><h3><font color='green'>The nameserver is active and authorized to handle this zone</font></h3>\n";
		edit_zone_attrs($zonedn);
		print_whois($zonename);
	} elseif ($auth==0) {
		print "<center><br><h3><font color='orange'>The nameserver is not active for this zone</font></h3>\n";
		edit_zone_attrs($zonedn);
		print_whois($zonename);
	} elseif ($auth==-1) {
		print "<center><br><h3><font color='red'>The nameserver is not authorized to handle this zone</font></h3>\n";
		edit_zone_attrs($zonedn);
		print_whois($zonename);
	} else {
		print "<br><H2 align='center'><font color='red'>Zone <I>$zonename</I> does not not belong to a valid TLD</font></H2>\n";
		delete_zone();
	}
}

function edit_zone_attrs($zonedn)
{
	global $ldap, $ZONE_INFO, $ZONEEDIT, $HTTP_GET_VARS, $HTTP_POST_VARS;
	if (isset($HTTP_GET_VARS[selet])) $selet = $HTTP_GET_VARS[selet]; elseif (isset($HTTP_POST_VARS[selet])) $selet = $HTTP_POST_VARS[selet];
	$query = ldap_read($ldap, $zonedn, "(objectclass=dnszone)");
	$entries = ldap_get_entries($ldap, $query);
	$zonename = $entries[0][dnszonename][0];
	ldap_free_result($query);
	$zonedn = $entries[0][dn];
	$zonename0 = $entries[0][dnszonename][0];
	$zonenames = array();
	for ($i = 1; $i<$entries[0][dnszonename][count]; $i++) {
		array_push($zonenames, $entries[0][dnszonename][$i]);
	}
	$zonedata = array();
	foreach ($ZONE_INFO as $za) {
		$zonedata[$za] = $entries[0][$za][0];
	}

	print "<center><h2>Edit DNS zone <I>$zonename0</I></h2>";
	$zoneconstr = check_constraint($zonedn);
	if (ereg("[a]", $zoneconstr)) {
		# Print modifiable table for SOA
		if (ereg("[f]", $selet)) {
			print "<form method='POST' action='$ZONEEDIT' target='main' enctype='multipart/form-data'>".
			    "<input type='hidden' name='call' value='editzone'>".
			    "<input type='hidden' name='zonedn' value='$zonedn'>";
		} else {
			print "<form method='POST' action='$ZONEEDIT' enctype='multipart/form-data'>".
			    "<input type='hidden' name='call' value='editzone'>".
			    "<input type='hidden' name='zonedn' value='$zonedn'>".
			    "<input type='hidden' name='selet' value='$selet'>";
		}
		print "<table border='1' width='85%' COLS='4' CELLSPACING='1' CELLPADDING='0'>\n";
		$zc = 0;
		foreach ($zonenames as $zn) {
			print "<tr><td align='right' colspan='2'> Aliasing Zonename: </td><td colspan='2'>";
			if (ereg("[a]", $zoneconstr))
				print "<input type='text' name='dnszonename$zc' value='$zn' size='40' maxlength='64'>";
			else
				print "<b>$zn</b>";
			print "</td></tr>\n";
			$zc++;
		}
		if (ereg("[a]", $zoneconstr)) {
			print "<tr><td align='right' colspan='2'> Add aliasing Zonename: </td><td colspan='2'>".
			    "<input type='text' name='dnszonename$zc' size='40' maxlength='64'></td></tr>\n";
		}
		print_zone_soa($zonedata, $zoneconstr);
		print "<tr><td colspan='4' align='center'><input type='submit' name='modifysoa' value='  Modify SOA for zone: \"$zonename0\"  '>".
		    "</td></tr></table><P></form>";
	} else {
		# Print non-modifiable table for SOA
		print "<table border='1' width='85%' COLS='4' CELLSPACING='1' CELLPADDING='0'>\n";
		foreach ($zonenames as $zn) {
			print "<tr><td align='right' colspan='2'> Aliasing Zonename: </td><td colspan='2'> <b>$zn</b></td></tr>\n";
		}
		print_zone_soa($zonedata, $zoneconstr);
		print "</table><P>\n";
	}

	# Tables for RRsets
	$query = ldap_list($ldap, $zonedn, "(objectclass=dnsrrset)");
	$rrsets = ldap_get_entries($ldap, $query);
	ldap_free_result($query);
	print "<table border='1' width='98%' COLS='5' CELLSPACING='1' CELLPADDING='0'>\n".
	    "<tr><th width='1%'>DNS Name</th><th width='1%'>Type</th><th width='250'>Mapping</th>".
	    "<th width='1%'>TTL/Pref</th><th width='1%'>&nbsp;</th></tr>\n";
	for ($i = 0; $i<$rrsets[count]; $i++) {
		$setdn = $rrsets[$i][dn];
		$setconstr = $zoneconstr.check_constraint($setdn);
		$domainname = $rrsets[$i][dnsdomainname][0];
		$ipaddr = $rrsets[$i][dnsipaddr];
		$cipaddr = $rrsets[$i][dnscipaddr][0];
		$cname = $rrsets[$i][dnscname][0];
		$type = $rrsets[$i][dnstype][0];
		$ttl = $rrsets[$i][dnsttl][0];
		$preference = $rrsets[$i][dnspreference][0];
		if (ereg("[amo]", $setconstr)) {
			if (ereg("[f]", $selet)) {
				print "<form method='POST' action='$ZONEEDIT' target='main' enctype='multipart/form-data'>".
				    "<input type='hidden' name='call' value='editzone'>".
				    "<input type='hidden' name='selet' value='$selet'>".
				    "<input type='hidden' name='zonedn' value='$zonedn'>".
				    "<input type='hidden' name='setdn' value='$setdn'>";
			} else {
				print "<form method='POST' action='$ZONEEDIT' enctype='multipart/form-data'>".
				    "<input type='hidden' name='call' value='editzone'>".
				    "<input type='hidden' name='zonedn' value='$zonedn'>".
				    "<input type='hidden' name='setdn' value='$setdn'>";
			}
		}
		if (ereg("[amo]", $setconstr)) {
			print "<br><input type='checkbox' name='deleterrset' value=' Delete '>Delete";
		}
		print "</td><td><b>$type</b></td><td><table border='0'>";
		if ($type=="CNAME" || $type=="MX" || $type=="NS") {
			print "<tr><td align='right'>CName:</td>";
			if (ereg("[amo]", $setconstr))
				print "<td><input type='text' name='dnscname' value='$cname' size='20' maxlength='64'></td></tr>\n";
			else
				print "<td><b>$cname</b></td></tr>\n";
		}
		if ($type=="A" || $type=="MX" || $type=="NS") {
			if (ereg("[a]", $setconstr)) {
				print "<tr><td align='right'>Canonical IP:</td>".
				    "<td><input type='text' name='dnscipaddr' value='$cipaddr' size='20' maxlength='15'></td></tr>\n";
			} else if (isset($cipaddr)) {
				print "<tr><td align='right'>Canonical IP:</td><td><b>$cipaddr</b></td></tr>\n";
			}
			for ($k = 0; $k<$rrsets[$i][dnsipaddr][count]; $k++) {
				print "<tr><td align='right'>Modify IP:</td>";
				$ipaddr = $rrsets[$i][dnsipaddr][$k];
				if (ereg("[amo]", $setconstr))
					print "<td><input type='text' name='dnsipaddr$k' value='$ipaddr' size='20' maxlength='15'></td></tr>\n";
				else
					print "<td><b>$ipaddr</b></td></tr>\n";
			}
			if (ereg("[amo]", $setconstr)) {
				print "<tr><td align='right'>Add IP: </td><td><input type='text' name='dnsipaddr$k' value='' size='20' maxlength='15'></td></tr>\n";
			}
		}
		print "</table></td>";
		if (ereg("[amo]", $setconstr)) {
			print "</td><td>TTL: <input type='text' name='dnsttl' value='$ttl' size='6' maxlength='6'>";
			if ($type=="MX")
			    print "<br>Pref: <input type='text' name='dnspreference' value='$preference' size='6' maxlength='6'>";
			print "</td><td><input type='submit' name='modifyrrset' value=' Modify '></td></tr></form>\n";
		} else {
			print "</td><td>TTL: <b>$ttl</b>";
			if ($type=="MX")
				print "<br>Pref: <b>$preference</b>";
			print "</td></tr>\n";
		}
	}
	if (ereg("[amo]", $setconstr)) {
		if (ereg("[f]", $selet)) {
			print "\n<form method='POST' action='$ZONEEDIT' target='main' enctype='multipart/form-data'>".
			    "<input type='hidden' name='call' value='editzone'>".
			    "<input type='hidden' name='selet' value='$selet'>".
			    "<input type='hidden' name='zonedn' value='$zonedn'";
		} else {
			print "\n<form method='POST' action='$ZONEEDIT' enctype='multipart/form-data'>".
			    "<input type='hidden' name='call' value='editzone'>".
			    "<input type='hidden' name='zonedn' value='$zonedn'";
		}
		print "<tr><td align='center'><input type='text' name='dnsdomainname' size='12' maxlength='32' override='1'></td>".
		    "<td align='center'><select name='dnstype'><option value='CNAME'>CNAME</option><option value='A'>A</option>".
		    "<option value='MX'>MX</option><option value='NS'>NS</option><option value='PTR'>PTR</option>".
		    "<option value='TXT'>TXT</option></select></td>".
		    "<td>&nbsp;</td><td colspan='2' align='center'><input type='submit' name='addrrset' value=' Add new record '></td></tr>".
		    "</form>";
	}
	print "</table><P>\n";

	print "<table border='1' COLS='2' width='66%'><tr>";
	// 'Delete' form
	$onclick = "if(confirm('Do you really want to remove zone: $zonename0 and all its resource records?'))";
	if (ereg("[f]", $selet)) {
		$onclick .= "{ parent.frames.menu.location='$ZONEEDIT?call=dnslist&selet=$selet&wait=1';".
		"parent.frames.main.location='$ZONEEDIT?call=removezone&zonedn=$zonedn&selet=$selet'; }";
	} else {
		$onclick .= "{ parent.window.location='$ZONEEDIT?call=removezone&zonedn=$zonedn'; }";
	}
	if (ereg("[am]", $setconstr)) {
		print "<form><td align='center'><INPUT TYPE='BUTTON' VALUE=' Delete Zone \"$zonename0\" ' ONCLICK=\"$onclick\"></td></form>\n";
	}

	// form for reset/refresh button
	if (ereg("[f]", $selet)) {
		print "<form method='POST' action='$ZONEEDIT' target='main' enctype='multipart/form-data'>".
		    "<input type='hidden' name='call' value='editzone'>".
		    "<input type='hidden' name='zonedn' value='$zonedn'>".
		    "<input type='hidden' name='selet' value='$selet'>";
	} else {
		print "<form method='POST' action='$ZONEEDIT' enctype='multipart/form-data'>".
		    "<input type='hidden' name='call' value='editzone'>".
		    "<input type='hidden' name='zonedn' value='$zonedn'>";
	}
	print "<td align='center'><input type='submit' name='resetform' value='  Reset and Refresh  '></td></form>".
	    "</tr></table>\n";
}

function new_zone($new_zonename = "")
{
	global $HTTP_GET_VARS, $ZONE_SOA, $ZONEEDIT, $BASEDN;
	if (isset($HTTP_GET_VARS[selet])) $selet = $HTTP_GET_VARS[selet];
	$zonedata = $ZONE_SOA;
	$zonedata[dnsserial] = new_serial();
	$onsubmit = "{ parent.frames.menu.location='$ZONEEDIT?call=dnslist&selet=$selet&wait=1'; }";
	print "<center><h2>Add new DNS zone</h2>";
	print "<form action='$ZONEEDIT' method='POST' target='main' enctype='multipart/form-data' onsubmit=\"$onsubmit\">".
	    "<input type='hidden' name='call' value='addzone'>".
	    "<input type='hidden' name='selet value='$selet'>".
	    "<table border='1' width='85%' COLS='4'>\n".
	    "<tr><td align='right' colspan='2'> New Zonename: </td><td colspan='2'>".
	    "<input type='text' name='dnszonename' size='40' maxlength='64' value='".(strlen($new_zonename)>3 ? $new_zonename : "")."'>".
	    "</td></tr>\n"; 
	print_zone_soa($zonedata, check_constraint());
	print "</td></tr><tr><td colspan='2' align='center'>".
	    "<input type='submit'>".
	    "</td><td colspan='2' align='center'>".
	    "<input type='reset'>".
	    "</td></tr></table>\n".
	    "</form>";
}

function add_zone()
{
	global $ldap, $HTTP_POST_VARS, $BASEDN, $ZONE_SOA, $ZONE_ENTRY, $ZONE_INFO;
	$zonedata = array();
	foreach ($ZONE_INFO as $za) {
		if (strlen($HTTP_POST_VARS[$za])>0) {
			$zonedata[$za] = $HTTP_POST_VARS[$za];
		}
	}
	$zonedata["cn"] = $zonedata["dnszonename"];
	$zonedata["objectclass"] = "dnszone";
	$zonedn = "cn=$zonedata[cn],$BASEDN";
	ldap_add($ldap, $zonedn, $zonedata) or die("Failed to add zonedn: $zonedn");
	
	foreach ($ZONE_ENTRY as $ze) {
		$dnch = "cn=$ze[cn],$zonedn";
		ldap_add($ldap, $dnch, $ze) or die("Failed to add rrset dn: $dnch");
	}
	return $zonedn;
}

function remove_zone($zonedn)
{
	global $ldap;
	$query = ldap_list($ldap, $zonedn, "(objectclass=DNSrrset)");
	$entries = ldap_get_entries($ldap, $query);
	ldap_free_result($query);
	for ($i = 0; $i<$entries[count]; $i++) {
		ldap_delete($ldap, $entries[$i][dn]) or die("Failed to delete dn: $entries[$i][dn]");
	}
	ldap_delete($ldap, $zonedn) or die("Failed to delete dn: $zonedn");
	return 1;
}

function new_serial($zonedn = 0)
{
	global $ldap;
	$newserial = date("Ymd")."00";
	if ($zonedn) {
		$query  = ldap_read($ldap, $zonedn, "(objectclass=DNSzone)");
		$entries = ldap_get_entries($ldap, $query);
		$oldserial = $entries[0][dnsserial][0];
	}
	return ($newserial>$oldserial) ? $newserial : $oldserial+1;
}

function add_rrset($zonedn)
{
	global $ldap, $binddn, $HTTP_POST_VARS, $DEFAULT_TTL, $DEFAULT_PREFERENCE;
	if (!isset($HTTP_POST_VARS[dnsdomainname])) die("No domainname specified");
	if (strlen($HTTP_POST_VARS[dnsdomainname])>0)
		$entry[dnsdomainname] = $HTTP_POST_VARS[dnsdomainname];
	if (!isset($HTTP_POST_VARS[dnstype])) die("No type specified");
	$entry[dnstype] = $HTTP_POST_VARS[dnstype];
	$entry[dnsclass] = "IN"; // INternet is hardcoded
	$entry[dnsttl] = $DEFAULT_TTL;
	// $entry[owner] = $binddn;
	if ($entry[dnstype]=="MX" || $entry[dnstype]=="NS") {
		for ($i = 1;; $i++) {
			$setcn = "$entry[dnstype]$i:$entry[dnsdomainname]";
			$query = ldap_list($ldap, $zonedn, "(&(objectclass=dnsrrset)(cn=$setcn))");
			$rrset = ldap_get_entries($ldap, $query);
			ldap_free_result($query);
			if ($rrset[count]==0)
				break;
		}
		if ($entry[dnstype]=="MX")
			$entry[dnspreference] = $DEFAULT_PREFERENCE;
	} else {
		$setcn = "$entry[dnstype]:$entry[dnsdomainname]";
		$query = ldap_list($ldap, $zonedn, "(&(objectclass=dnsrrset)(cn=$setcn))");
		$rrset = ldap_get_entries($ldap, $query);
		ldap_free_result($query);
		if ($rrset[count]>0) {
			error_confirm("$entry[dnsdomainname] has already been added to this zone");
			return;
		}
	}
	$entry[objectclass] = "dnsrrset";
	$entry[cn] = $setcn;
	$setdn = "cn=$setcn,$zonedn";
	ldap_add($ldap, $setdn, $entry) or die("Faild to add DNSrrset $setdn to DNSzone $zonedn");
}

function modify_rrset($zonedn, $setdn)
{
	global $ldap, $HTTP_POST_VARS;
	$zonename = get_zone_name($zonedn);
	$entry = array();
	if (isset($HTTP_POST_VARS[dnscname])) {
		if ($HTTP_POST_VARS[dnscname]=="") {
			$entry[dnscname] = array();
		} elseif (ereg("\.$", $HTTP_POST_VARS[dnscname])) {
			if (checkdnsrr($HTTP_POST_VARS[dnscname], "A")) {
				$entry[dnscname] = $HTTP_POST_VARS[dnscname];
			} else {
				error_confirm("Error: $HTTP_POST_VARS[dnscname] does not resolve to a valid IP-address");
				return;
			}
		} elseif (isset($HTTP_POST_VARS[dnsipaddr0]) || isset($HTTP_POST_VARS[dnscipaddr])) {
			// records with their own address settings are not checked against DNS
			$entry[dnscname] = $HTTP_POST_VARS[dnscname];
		} else {
			if (!checkdnsrr("$HTTP_POST_VARS[dnscname].$zonename", "A")) {
				print "<br><h2 align='center'><font color='orange'>Warning: $HTTP_POST_VARS[dnscname].$zonename".
				    " does not resolve to a valid IP-address</font></h2>\n";
			}
			$entry[dnscname] = $HTTP_POST_VARS[dnscname];
		}
	}
	if (isset($HTTP_POST_VARS[dnscipaddr])) {
		if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", $HTTP_POST_VARS[dnscipaddr], $reg)) {
			$regip = "$reg[1].$reg[2].$reg[3].$reg[4]";
			if (check_unique_cipaddr($setdn, $regip))
				$entry[dnscipaddr] = $regip;
			else
				return;
		} elseif ($HTTP_POST_VARS[dnscipaddr]=="") {
			$entry[dnscipaddr] = array();
		} else {
			error_confirm("$HTTP_POST_VARS[dnscipaddr] is not a valid IP-address");
			return;
		}
	}
	if (isset($HTTP_POST_VARS[dnsttl])) {
		if (ereg("([0-9]+)", $HTTP_POST_VARS[dnsttl], $reg)) {
			$entry[dnsttl] = $reg[1];
		} else {
			error_confirm("$HTTP_POST_VARS[dnsttl] is not a valid Time To Live");
			return;
		}
	}
	if (isset($HTTP_POST_VARS[dnspreference])) {
		if (ereg("([0-9]+)", $HTTP_POST_VARS[dnspreference], $reg)) {
			$entry[dnspreference] = $reg[1];
		} else {
			error_confirm("$HTTP_POST_VARS[dnspreference] is not a valid MX-prefrence");
			return;
		}
	}
	$entry[dnsipaddr] = array();
	for ($i = 0; isset($HTTP_POST_VARS["dnsipaddr$i"]); $i++) {
		$ipaddr = $HTTP_POST_VARS["dnsipaddr$i"];
		if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", $ipaddr, $reg)) {
			array_push($entry[dnsipaddr], "$reg[1].$reg[2].$reg[3].$reg[4]");
		} elseif ($ipaddr!="") {
			error_confirm("$ipaddr is not a valid IP-address");
			return;
		}
	}
	ldap_modify($ldap, $setdn, $entry) or die("Faild to modify DNSrrest $setdn in DNSzone $zonedn");
	ldap_mod_replace($ldap, $zonedn, array("dnsserial"=>new_serial($zonedn)));
}

function delete_rrset($zonedn, $setdn)
{
	global $ldap;
	ldap_delete($ldap, $setdn) or die("Failed to delete $setdn from LDAP");;
	ldap_mod_replace($ldap, $zonedn, array("dnsserial"=>new_serial($zonedn)));
}

function check_unique_cipaddr($setdn, $cipaddr)
{
	global $ldap, $BASEDN;
	$query = ldap_search($ldap, $BASEDN, "(&(objectclass=dnsrrset)(dnscipaddr=$cipaddr))");
	$entries = ldap_get_entries($ldap, $query);
	ldap_free_result($query);
	for ($i = 0; $i<$entries[count]; $i++) {
		$dn = $entries[$i][dn];
		if ($dn!=$setdn) {
			error_confirm("Canonical IP-address $cipaddr is already used by $dn");
			return 0;
		}
	}
	return 1;
}

function print_whois($zonename)
{
	global $WHOISSERVERS;
	return; // weil unser FW-Gschaftler den Port 43 von innen nach aussen zugedreht hat

	if (ereg("\.([a-zA-Z]+)$", $zonename, $regex)) {
		$whoissrv = $WHOISSERVERS["$regex[1]"];
		if (isset($whoissrv)) {
			$whoisrecord = system("whois -h $whoissrv $zonename");
			print "<h3 align='center'>Whois-record for zone <I>$zonename</I></h3><P>\n".
			    "as serverd by $whoissrv<br>\n".
			    "<table border='1' width='85%' CELLSPACING='1' CELLPADDING='0'><tr align='LEFT'>".
			    "<td><PRE>$whoisrecord</PRE></td></tr></table>\n";
		} else {
			print "<h3 align=center><font color=red>No WHOIS-Server found for \"$regex[1]\"</font></h3>\n";
		}
	}
}

?>
