/* Patch for tinydns to pass DNS-query to LDAP in favour of a cdb lookup.
 * $Id: askldap.c,v 1.8 2002/08/12 16:41:25 jrief Exp $
 * Copyright 2002 <jacob.rief@tiscover.com> 
 */ 

#include <lber.h>
#include <ldap.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <setjmp.h>
#include "alloc.h"
#include "byte.h"
#include "response.h"
#include "askldap.h"
#include "dns.h"

static LDAP* ldap_con;
static sigjmp_buf stack_context;

static struct {
	char ldaphosts[256];
	const char* basedn;
	char binddn[256];
	char bindpwd[16];
	struct timeval timeout;	
	int verbose;
	int initialized;
} options;

struct zonerecord {
	char zonedn[256];
	char zonename[64];
	char class[16];
	char type[16];
	char adminmailbox[64];
	char zonemaster[64];
	unsigned long serial, refresh, retry, expire, minimum;
	int ttl;
	int timestamp;
};

struct resourcerecord {
	char qualifieddomainname[256];
	char class[16];
	char type[16];
	char ipaddr[8][4];
	int numipaddrs;
	char cname[256];
	unsigned int preference;
	int ttl;
	int timestamp;
	int additionalinfo;
	struct resourcerecord* next;
};

enum { ASKLDAP_RETRY = 1, ASKLDAP_RETURN = 2, ASKLDAP_RECONNECT = 3 };
	
static
void assert_ldap(int err)
{
	static int retries;
	switch (err) {
	    case LDAP_SUCCESS:
		return;
	    case LDAP_TIMELIMIT_EXCEEDED:
		fprintf(stderr, "Warning: %s\n", ldap_err2string(err));
		retries++;
		if (retries<3)
			siglongjmp(stack_context, ASKLDAP_RETRY);
		retries = 0;
		siglongjmp(stack_context, ASKLDAP_RETURN);
	    case LDAP_TIMEOUT:
	    case LDAP_NO_SUCH_OBJECT:
		fprintf(stderr, "Warning: %s\n", ldap_err2string(err));
		siglongjmp(stack_context, ASKLDAP_RETURN);
	    case LDAP_BUSY:
	    case LDAP_UNAVAILABLE:
	    case LDAP_UNWILLING_TO_PERFORM:
	    case LDAP_SERVER_DOWN:
		fprintf(stderr, "Warning: %s\n", ldap_err2string(err));
		siglongjmp(stack_context, ASKLDAP_RECONNECT);
	    default:
		fprintf(stderr, "Fatal error: %s\n", ldap_err2string(err));
#ifdef _DEBUG
		abort();
#else
		exit(1);
#endif
	}
}

void free_domainrecords(struct resourcerecord* anchor)
{
	struct resourcerecord* ptr;
	for (ptr = anchor; ptr; ptr = anchor) {
		anchor = anchor->next;
		alloc_free(ptr);
	}	
}

static
void fill_resourcerecord(struct resourcerecord* rr, LDAPMessage* m, const char* zonename)
{
	BerElement* ber = NULL;
	char* attr;
		
	byte_zero(rr, sizeof(struct resourcerecord));
	strcpy(rr->class, "IN");
	for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
		struct berval** bvals = ldap_get_values_len(ldap_con, m, attr);
		if (bvals && bvals[0] && bvals[0]->bv_len>0) {
			if (strcasecmp(attr, "dnsdomainname")==0) {
				char tmp[64];
				if (sscanf(bvals[0]->bv_val, "%64s", tmp)==1) {
					if (zonename[0]!='\0') 
						snprintf(rr->qualifieddomainname, 256, "%s.%s", tmp, zonename);
					else
						strncpy(rr->qualifieddomainname, tmp, 256);
				}
			} else if (strcasecmp(attr, "dnstype")==0) {
				if (sscanf(bvals[0]->bv_val, "%16s", rr->type)!=1) {
					rr->type[0] = '\0';
				}
			} else if (strcasecmp(attr, "dnsipaddr")==0) {
				int k, ip[4];
				for (k = 0; bvals[k] && k < 8-rr->numipaddrs; k++) {
					if (sscanf(bvals[k]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
						rr->ipaddr[rr->numipaddrs][0] = (char)ip[0];
						rr->ipaddr[rr->numipaddrs][1] = (char)ip[1];
						rr->ipaddr[rr->numipaddrs][2] = (char)ip[2];
						rr->ipaddr[rr->numipaddrs][3] = (char)ip[3];
						rr->numipaddrs++;
					}
				}
			} else if (rr->numipaddrs<8 && strcasecmp(attr, "dnscipaddr")==0) {
				int ip[4];
				if (sscanf(bvals[0]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
					rr->ipaddr[rr->numipaddrs][0] = (char)ip[0];
					rr->ipaddr[rr->numipaddrs][1] = (char)ip[1];
					rr->ipaddr[rr->numipaddrs][2] = (char)ip[2];
					rr->ipaddr[rr->numipaddrs][3] = (char)ip[3];
					rr->numipaddrs++;
				}
			} else if (strcasecmp(attr, "dnscname")==0) {
				if (sscanf(bvals[0]->bv_val, "%256s", rr->cname)==1) {
					int len = strlen(rr->cname);
					if (rr->cname[len-1]!='.' && zonename[0]!='\0') {
						strcat(rr->cname, ".");
						strncat(rr->cname, zonename, 252-len);
						strcat(rr->cname, ".");
					}
				} else {
					rr->cname[0] = '\0';
				}
			} else if (strcasecmp(attr, "dnsttl")==0) {
				if (sscanf(bvals[0]->bv_val, "%d", &rr->ttl)!=1)
					rr->ttl = 0;
			} else if (strcasecmp(attr, "dnstimestamp")==0) {
				if (sscanf(bvals[0]->bv_val, "%d", &rr->timestamp)!=1)
					rr->timestamp = 0;
			} else if (strcasecmp(attr, "dnspreference")==0) {
				if (sscanf(bvals[0]->bv_val, "%u", &rr->preference)!=1)
					rr->preference = 1;
			}
		}
		ldap_value_free_len(bvals);
	}
	if (rr->qualifieddomainname[0]=='\0')
		strncpy(rr->qualifieddomainname, zonename, 256);
}

static
void fill_zonerecord(struct zonerecord* zone, LDAPMessage* m)
{
	BerElement* ber = NULL;
	char* attr;

	byte_zero(zone, sizeof(struct zonerecord));
	strcpy(zone->class, "IN");
	for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
		struct berval** bvals = ldap_get_values_len(ldap_con, m, attr);
		if (bvals && bvals[0] && bvals[0]->bv_len>0) {
			if (strcasecmp(attr, "dnstype")==0) {
				if (sscanf(bvals[0]->bv_val, "%16s", zone->type)!=1)
					zone->type[0] = '\0';
			} else if (strcasecmp(attr, "dnsserial")==0) {
				if (sscanf(bvals[0]->bv_val, "%lu", &zone->serial)!=1)
					zone->serial = 0;
			} else if (strcasecmp(attr, "dnsrefresh")==0) {
				if (sscanf(bvals[0]->bv_val, "%lu", &zone->refresh)!=1)
					zone->refresh = 0;
			} else if (strcasecmp(attr, "dnsretry")==0) {
				if (sscanf(bvals[0]->bv_val, "%lu", &zone->retry)!=1)
					zone->retry = 0;
			} else if (strcasecmp(attr, "dnsexpire")==0) {
				if (sscanf(bvals[0]->bv_val, "%lu", &zone->expire)!=1)
					zone->expire = 0;
			} else if (strcasecmp(attr, "dnsminimum")==0) {
				if (sscanf(bvals[0]->bv_val, "%lu", &zone->minimum)!=1)
					zone->minimum = 0;
			} else if (strcasecmp(attr, "dnsadminmailbox")==0) {
				if (sscanf(bvals[0]->bv_val, "%64s", zone->adminmailbox)!=1)
					zone->adminmailbox[0] = '\0';
			} else if (strcasecmp(attr, "dnszonemaster")==0) {
				if (sscanf(bvals[0]->bv_val, "%64s", zone->zonemaster)!=1)
					zone->zonemaster[0] = '\0';
			} else if (strcasecmp(attr, "dnsttl")==0) {
				if (sscanf(bvals[0]->bv_val, "%d", &zone->ttl)!=1)
					zone->ttl = 0;
			} else if (strcasecmp(attr, "dnstimestamp")==0) {
				if (sscanf(bvals[0]->bv_val, "%d", &zone->timestamp)!=1)
					zone->timestamp = 0;
			} else if (strcasecmp(attr, "dnszonename")==0) {
				if (sscanf(bvals[0]->bv_val, "%s", zone->zonename)!=1)
					zone->zonename[0] = '\0';
			}
		}
		ldap_value_free_len(bvals);
	}
}

static
int find_ipaddr(const char* queryname, char ip[4])
{
	static char *rrattrs[] = { "dnsipaddr", "dnscipaddr", 0 };
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ret = 0;
	char filter[256], domainname[64];
	const char *zonename = queryname;
	domainname[0] = '\0';
	while (*zonename) {
		int len = snprintf(filter, 256, "(&(dnszonename=%s", zonename);
		if (filter[len-1]=='.')
			filter[len-1] = '\0';
	        strncat(filter, ")(objectclass=dnszone)(dnsclass=IN))", 256-len);
		assert_ldap(ldap_search_st(ldap_con, options.basedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
		if (m = ldap_first_entry(ldap_con, res)) {
			char* zonedn = ldap_get_dn(ldap_con, m);
			if (ldap_next_entry(ldap_con, m))
				printf("Warning: ambigous zonename for %s in %s\n", zonename, zonedn);
			if (domainname[0]!='\0') {
				len = strlen(domainname);
				if (domainname[len-1]=='.')
					domainname[len-1] = '\0';
				snprintf(filter, 256, "(&(|(dnsdomainname=%s)(dnscname=%s))(objectclass=dnsrrset)(dnsclass=IN)(|(dnsipaddr=*)(dnscipaddr=*)))", domainname, domainname);
			} else {
				strcpy(filter, "(&(!(dnsdomainname=*))(objectclass=dnsrrset)(dnsclass=IN)(|(dnsipaddr=*)(dnscipaddr=*)))");
			}
			ldap_msgfree(res);
			assert_ldap(ldap_search_st(ldap_con, zonedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
			if (m = ldap_first_entry(ldap_con, res)) {
				struct resourcerecord rr;
				fill_resourcerecord(&rr, m, "");
				if (rr.numipaddrs>0) {
					rr.numipaddrs = rand()%rr.numipaddrs;
					ip[0] = rr.ipaddr[rr.numipaddrs][0];
					ip[1] = rr.ipaddr[rr.numipaddrs][1];
					ip[2] = rr.ipaddr[rr.numipaddrs][2];
					ip[3] = rr.ipaddr[rr.numipaddrs][3];
					ret = 1;
				}
			}
			ldap_memfree(zonedn);
			ldap_msgfree(res); res = NULL;
			if (ret)
				return 1;
			break;
		}
		while (*zonename && *zonename!='.') {
			domainname[zonename-queryname] = *zonename;
			zonename++;
		}
		domainname[zonename-queryname] = *zonename;
		if (*zonename=='.') {
			zonename++;
			domainname[zonename-queryname] = '\0';
		}
	}
	/* sometimes the queryname resolves directly as cname in some other records */
	snprintf(filter, 256, "(&(dnscname=%s)(objectclass=dnsrrset)(dnsclass=IN)(|(dnsipaddr=*)(dnscipaddr=*)))", queryname);
	assert_ldap(ldap_search_st(ldap_con, options.basedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
	if (m = ldap_first_entry(ldap_con, res)) {
		struct resourcerecord rr;
		fill_resourcerecord(&rr, m, "");
		if (rr.numipaddrs>0) {
			rr.numipaddrs = rand()%rr.numipaddrs;
			ip[0] = rr.ipaddr[rr.numipaddrs][0];
			ip[1] = rr.ipaddr[rr.numipaddrs][1];
			ip[2] = rr.ipaddr[rr.numipaddrs][2];
			ip[3] = rr.ipaddr[rr.numipaddrs][3];
			ret = 1;
		}
	}
	ldap_msgfree(res);
	return ret;
}

static
struct resourcerecord* find_reverserecord(const char* queryname, int ip[4])
{
	static char *rrattrs[] = { "dnstype", "dnsdomainname", "dnscname", "dnsttl", 0 };
	LDAPMessage* res = NULL;
	struct resourcerecord* rr = NULL;
	LDAPMessage* m;
	char filter[256];
	snprintf(filter, 256, "(&(dnscipaddr=%u.%u.%u.%u)(objectclass=dnsrrset)(dnsclass=IN))", ip[0], ip[1], ip[2], ip[3]);
	assert_ldap(ldap_search_st(ldap_con, options.basedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
	if (m = ldap_first_entry(ldap_con, res)) {
		char* rrsetdn = ldap_get_dn(ldap_con, m);
		char** explodedn = NULL;
		
		rr = (void*)alloc(sizeof(struct resourcerecord));
		fill_resourcerecord(rr, m, "");
		if (ldap_next_entry(ldap_con, m))
			printf("Warning: ambigous IP-address for %u.%u.%u.%u in dn: %s\n", ip[0], ip[1], ip[2], ip[3], rrsetdn);
		explodedn = ldap_explode_dn(rrsetdn, 0);
		if (explodedn[0]) {
			static char *zoneattrs[] = { "dnszonename", 0 };
			char zonedn[256];
			int i, len = 0;
			struct zonerecord zone;

			zonedn[0] = '\0';
			for (i = 1; explodedn[i]; i++)
				len += snprintf(zonedn+len, 256-len, "%s,", explodedn[i]);
			zonedn[len-1] = '\0';
			ldap_msgfree(res);
			assert_ldap(ldap_search_st(ldap_con, zonedn, LDAP_SCOPE_SUBTREE, "(objectclass=dnszone)", zoneattrs, 0, &options.timeout, &res));
			m = ldap_first_entry(ldap_con, res);
			if (m==NULL)
				printf("Error: parent dn: %s not found for %s\n", zonedn, rrsetdn);
			fill_zonerecord(&zone, m);
			len = strlen(rr->qualifieddomainname);
			if (len==0) {
				len = strlen(rr->cname);
				if (rr->cname[len-1]!='.') {
					strcat(rr->cname, ".");
					strncat(rr->cname, zone.zonename, 252-len);
				}
			} else {
				/* in those situations where a dnsrrset
				 * defines something like MX or NS for a zone
				 * and also sets a canonical name for the
				 * service. */
				snprintf(rr->cname, 256, "%s.%s", rr->qualifieddomainname, zone.zonename);
			}
			strcpy(rr->type, "PTR");
			strncpy(rr->qualifieddomainname, queryname, 256);
		}
		ldap_memfree(rrsetdn);
		ldap_value_free(explodedn);
	}
	ldap_msgfree(res);
	return rr;
}

static
struct resourcerecord* read_domainrecords(const char* zonedn, const char* domainname, const char* zonename)
{
	static char *rrattrs[] = { "dnsdomainname", "dnstype", "dnsttl", "dnscname", "dnsipaddr", "dnscipaddr", "dnstimestamp", "dnspreference", 0 };
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	char filter[256];
	struct resourcerecord *prev, *anchor = NULL;
	
	if (domainname[0]) {
		if (strstr(zonename, "in-addr.arpa")) {
			unsigned int ip[4];
			char queryname[256];
			snprintf(queryname, 256, "%s.%s", domainname, zonename);
			if (sscanf(queryname, "%3u.%3u.%3u.%3u", &ip[3], &ip[2], &ip[1], &ip[0])!=4)
				return NULL;
			snprintf(filter, 256, "(&(dnsipaddr=%u.%u.%u.%u)(objectclass=dnsrrset)(dnsclass=IN))", ip[0], ip[1], ip[2], ip[3]);
			assert_ldap(ldap_search_st(ldap_con, zonedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
			if (m = ldap_first_entry(ldap_con, res)) {
				struct resourcerecord* rr;
				rr = (void*)alloc(sizeof(struct resourcerecord));
				fill_resourcerecord(rr, m, zonename);
				strncpy(rr->qualifieddomainname, queryname, 256);
				ldap_msgfree(res);
				return rr;
			} else {
				/* ipaddr not in our baliwick, search the whole tree for canonical ipaddr */
				ldap_msgfree(res);
				return find_reverserecord(queryname, ip);
			}
		} else {
			snprintf(filter, 256, "(&(dnsdomainname=%s)(objectclass=dnsrrset)(dnsclass=IN))", domainname);
			assert_ldap(ldap_search_st(ldap_con, zonedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
		}
	} else {
		snprintf(filter, 256, "(&(!(dnsdomainname=*))(objectclass=dnsrrset)(dnsclass=IN))");
		assert_ldap(ldap_search_st(ldap_con, zonedn, LDAP_SCOPE_SUBTREE, filter, rrattrs, 0, &options.timeout, &res));
	}
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		struct resourcerecord* rr;
		rr = (void*)alloc(sizeof(struct resourcerecord));
		fill_resourcerecord(rr, m, zonename);
		if (anchor==NULL) {
			prev = anchor = rr;
		} else {
			prev->next = rr;
			prev = rr;
		}
		if (options.verbose&1)
			printf("\trr: %s %s\n", domainname, rr->type);
	}
	ldap_msgfree(res);
	return anchor;
}

static
int read_dnszone(struct zonerecord* zone, const char* zonename)
{
	static char *zoneattrs[] = { "dnszonename", "dnstype", "dnsserial", "dnsrefresh", "dnsretry", "dnsexpire", "dnsminimum", "dnszonemaster", "dnsadminmailbox", "dnsttl", "dnstimestamp", 0 };
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	char* dn;
	char filter[256];
	
	snprintf(filter, 256, "(&(dnszonename=%s)(objectclass=dnszone)(dnsclass=IN))", zonename);
	assert_ldap(ldap_search_st(ldap_con, options.basedn, LDAP_SCOPE_SUBTREE, filter, zoneattrs, 0, &options.timeout, &res));
	m = ldap_first_entry(ldap_con, res);
	if (m==NULL) {
		ldap_msgfree(res);
		return 0;
	}
	dn = ldap_get_dn(ldap_con, m);
	fill_zonerecord(zone, m);
	m = ldap_next_entry(ldap_con, m);
	if (m) {
		char* otherdn = ldap_get_dn(ldap_con, m);
		printf("Warning: ambigous zonename found in dn: %s and dn: %s\n", dn, otherdn);
		ldap_memfree(otherdn);
	}
	strncpy(zone->zonedn, dn, 256);
	ldap_memfree(dn);
	ldap_msgfree(res);
	return 1;
}

static
void djb_name(const char* dotname, char* djbname)
{
	const char* c = dotname;
	int i, k;
	for (i = 0; *c; c++) {
		k = i;
		while (*c!='.') {
			k++;
			djbname[k] = *c;
			if (*c=='\0') {
				djbname[i] = k-i-1;
				return;
			}
			c++;
		}
		djbname[i] = k-i;
		i = k+1;
	}
	djbname[i] = '\0';
}

static
void djb_type(const char* dottype, char djbtype[2])
{
	djbtype[0] = '\0';
	if (strcasecmp(dottype, "A")==0)
		djbtype[1] = 001;
	else if (strcasecmp(dottype, "NS")==0)
		djbtype[1] = 002;
	else if (strcasecmp(dottype, "CNAME")==0)
		djbtype[1] = 005;
	else if (strcasecmp(dottype, "SOA")==0)
		djbtype[1] = 006;
	else if (strcasecmp(dottype, "PTR")==0)
		djbtype[1] = 014;
	else if (strcasecmp(dottype, "MX")==0)
		djbtype[1] = 017;
	else if (strcasecmp(dottype, "TXT")==0)
		djbtype[1] = 020;
}

static
void split_djbstyle(const char* djbname, char* domainname, char* zonename, int offset)
{
	int i, k, m = 0, n = 0;
	for (i = *djbname; i; i = *++djbname) {
		if (offset>0) {
			offset--;
			for (k = m; k<m+i; k++) {
				domainname[k] = *++djbname;
			}
			domainname[k] = '.';
			m = k+1;
		} else {
			for (k = n; k<n+i; k++) {
				zonename[k] = *++djbname;
			}
			zonename[k] = '.';
			n = k+1;
		}
	}
	domainname[m>0 ? m-1 : 0] = '\0';
	zonename[n>0 ? n-1 : 0] = '\0';
}

static
void build_response_section(struct resourcerecord *rr, char qtype[2], int section)
{
	char djbname[256], djbtype[2];
	djb_name(rr->qualifieddomainname, djbname);
	djb_type(rr->type, djbtype);
	if (byte_equal(djbtype, 2, DNS_T_A)) {
		if (byte_equal(qtype, 2, DNS_T_A) || byte_equal(qtype, 2, DNS_T_ANY)) {
			response_rstart(djbname, djbtype, rr->ttl);
			response_addbytes(rr->ipaddr[rand()%rr->numipaddrs], 4);
			response_rfinish(section);
		}
	} else if (byte_equal(djbtype, 2, DNS_T_CNAME)) {
		response_rstart(djbname, djbtype, rr->ttl);
		djb_name(rr->cname, djbname);
		response_addname(djbname);
		response_rfinish(section);
	} else if (byte_equal(djbtype, 2, DNS_T_NS)) {
		if (byte_equal(qtype, 2, DNS_T_NS) || byte_equal(qtype, 2, DNS_T_ANY)) {
			response_rstart(djbname, djbtype, rr->ttl);
			if (rr->cname[0]) {
				djb_name(rr->cname, djbname);
				response_addname(djbname);
				rr->additionalinfo = 1;
			} else {
				response_addbytes(rr->ipaddr[rand()%rr->numipaddrs], 4);
			}
			response_rfinish(section);
		}
	} else if (byte_equal(djbtype, 2, DNS_T_PTR)) {
		response_rstart(djbname, djbtype, rr->ttl);
		djb_name(rr->cname, djbname);
		response_addname(djbname);
		response_rfinish(section);
	} else if (byte_equal(djbtype, 2, DNS_T_MX)) {
		if (byte_equal(qtype, 2, DNS_T_MX) || byte_equal(qtype, 2, DNS_T_ANY)) {
			char tmp[2];
			response_rstart(djbname, djbtype, rr->ttl);
			tmp[0] = rr->preference/0x100;
			tmp[1] = rr->preference%0x100;
			response_addbytes(tmp, 2);
			if (rr->cname[0]) {
				djb_name(rr->cname, djbname);
				response_addname(djbname);
				rr->additionalinfo = 1;
			} else {
				response_addbytes(rr->ipaddr[rand()%rr->numipaddrs], 4);
			}
			response_rfinish(section);
		}
	}
}

static
void build_soa_section(struct zonerecord *zone, int section)
{
	time_t now;
	char defaultsoa[20];
	char djbname[256];
	char zonesoa[20];
	unsigned long tmp;
	time(&now);
	djb_name(zone->zonename, djbname);
	response_rstart(djbname, DNS_T_SOA, zone->ttl);
	djb_name(zone->zonemaster, djbname);
	response_addname(djbname);
	djb_name(zone->adminmailbox, djbname);
	response_addname(djbname);
	uint32_pack_big(defaultsoa, now);
	if (byte_equal(defaultsoa,4,"\0\0\0\0"))
	defaultsoa[3] = 1;
	byte_copy(defaultsoa + 4, 16, "\0\0\100\000\0\0\010\000\0\020\000\000\0\0\012\000");
	if (zone->serial==0)
		uint32_unpack_big(defaultsoa, &tmp);
	else
		tmp = zone->serial;
	uint32_pack_big(zonesoa, tmp);
	if (zone->refresh==0)
		uint32_unpack_big(defaultsoa+4, &tmp);
	else
		tmp = zone->refresh;
	uint32_pack_big(zonesoa+4, tmp);
	if (zone->retry==0)
		uint32_unpack_big(defaultsoa+8, &tmp);
	else
		tmp = zone->retry;
	uint32_pack_big(zonesoa+8, tmp);
	if (zone->expire==0)
		uint32_unpack_big(defaultsoa+12, &tmp);
	else
		tmp = zone->expire;
	uint32_pack_big(zonesoa+12, tmp);
	if (zone->minimum==0)
		uint32_unpack_big(defaultsoa+16, &tmp);
	else
		tmp = zone->minimum;
	uint32_pack_big(zonesoa+16, tmp);
	response_addbytes(zonesoa, 20);
	response_rfinish(section);
}

static
void build_additional_section(struct resourcerecord *rr)
{
	char djbname[256], ip[4];
	if (rr->additionalinfo && find_ipaddr(rr->cname, ip)) {
		djb_name(rr->cname, djbname);
		response_rstart(djbname, DNS_T_A, rr->ttl);
		response_addbytes(ip, 4);
		response_rfinish(RESPONSE_ADDITIONAL);
	}
}

static
int connect_and_bind()
{
	ldap_con = ldap_init(options.ldaphosts, LDAP_PORT);
	if (ldap_simple_bind_s(ldap_con, options.binddn, options.bindpwd)==LDAP_SUCCESS) {
		printf("Connected to %s as \"%s\"\n", options.ldaphosts, options.binddn);
		return 1;
	}
	ldap_con = NULL;
	return 0;
}

int askldap_query(const char* djbdomainname, char qtype[2])
{
	int offset;
	char domainname[64], zonename[64];
	struct zonerecord zoneinfo;
	int answer_ok = 0, flagsoa = 0, flagns = 0;
	if (!options.initialized)
		return 0;
	switch (sigsetjmp(stack_context, 1)) {
	    default:
		    if (ldap_con==NULL && !connect_and_bind())
		    	return answer_ok;
		    break;
	    case ASKLDAP_RECONNECT:
		    if (connect_and_bind())
			    break;
		    return answer_ok;
	    case ASKLDAP_RETURN:
		    return answer_ok;
	}
	for (offset = 0; offset<32; offset++) {
		struct resourcerecord *rransw, *rrauth, *rr;
		
		split_djbstyle(djbdomainname, domainname, zonename, offset);
		if (zonename[0]=='\0') return 0;
		if (!read_dnszone(&zoneinfo, zonename))
			continue;
		rransw = read_domainrecords(zoneinfo.zonedn, domainname, zonename);
		rrauth = NULL;
		if (offset==0) {
			/* query is in our bailiwick */
			if (byte_equal(qtype, 2, DNS_T_ANY) || byte_equal(qtype, 2, DNS_T_SOA)) {
				build_soa_section(&zoneinfo, RESPONSE_ANSWER);
				flagsoa = 1;
			}
			for (rr = rransw; rr; rr = rr->next) {
				build_response_section(rr, qtype, RESPONSE_ANSWER);
				answer_ok = 1;
			}
			if (!flagsoa) {
				build_soa_section(&zoneinfo, RESPONSE_AUTHORITY);
				flagsoa = 1;
			}
			if (!byte_equal(qtype, 2, DNS_T_ANY) && !byte_equal(qtype, 2, DNS_T_NS)) {
				for (rr = rransw; rr; rr = rr->next)
					if (strcmp(rr->type, "NS")==0) {
						build_response_section(rr, DNS_T_NS, RESPONSE_AUTHORITY);
						flagns = 1;
					}
			}
		} else {
			for (rr = rransw; rr; rr = rr->next) {
				if (strcmp(rr->type, "NS")==0) {
					build_response_section(rr, qtype, RESPONSE_AUTHORITY);
					flagns = 1;
				}
			}
			if (!flagns) {
				for (rr = rransw; rr; rr = rr->next) {
					build_response_section(rr, qtype, RESPONSE_ANSWER);
					answer_ok = 1;
				}
				if (answer_ok) {
					rrauth = read_domainrecords(zoneinfo.zonedn, "", zonename);
				} else {
					build_soa_section(&zoneinfo, RESPONSE_AUTHORITY);
					flagsoa = 1;
				}
			}
			for (rr = rrauth; rr; rr = rr->next) {
				if (strcmp(rr->type, "NS")==0) {
					build_response_section(rr, DNS_T_NS, RESPONSE_AUTHORITY);
					flagns = 1;
				}
			}
		}
		for (rr = rransw; rr; rr = rr->next)
			build_additional_section(rr);
		for (rr = rrauth; rr; rr = rr->next)
			build_additional_section(rr);
		free_domainrecords(rransw);
		free_domainrecords(rrauth);
		break;
	}
	return answer_ok || flagsoa || flagns;
}

void askldap_init(const char* ldaphost, const char* basedn, const char* binddn, const char* passwd)
{
	strncpy(options.ldaphosts, ldaphost, 256);
	options.basedn = basedn;
	if (binddn) strncpy(options.binddn, binddn, 256);
	if (passwd) strncpy(options.bindpwd, passwd, 16);
	/* LDAP timeout is hardcoded to 2/10 second.
	 * This must be enough because bindoperations usually
	 * timeout after one second and here we usually have to
	 * send five queries to the LDAP-server */
	options.timeout.tv_sec = 1;
	options.timeout.tv_usec = 200000;
	options.verbose = 0;
	options.initialized = 1;
	connect_and_bind();
}

