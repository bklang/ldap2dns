/* Patch for tinydns to pass DNS-query to LDAP in favour of a cdb lookup.
 * $Id: askldap.h,v 1.8 2002/08/12 16:41:25 jrief Exp $
 * Copyright 2002 <jacob.rief@tiscover.com> 
 */ 

extern
int askldap_query(const char* djbdomainname, char qtype[2]);
	
extern
void askldap_init(const char* ldaphost, const char* basedn, const char* binddn, const char* passwd);
