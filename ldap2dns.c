/*
 * Create data from an LDAP directory service to be used for tinydns
 * $Id: ldap2dns.c,v 1.20 2000/12/12 09:48:07 jrief Exp $
 * Copyright 2000 by Jacob Rief <jacob.rief@tiscover.com>
 * License: GPL version 2 or later. See http://www.fsf.org for details
 */

#include <lber.h>
#include <ldap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define UPDATE_INTERVALL 59
#define LDAP_CONF "/etc/openldap/ldap.conf"

#if defined WITH_TINYDNS
# include "uint16.h"
# include "uint32.h"
# include "str.h"
# include "byte.h"
# include "fmt.h"
# include "ip4.h"
# include "exit.h"
# include "readwrite.h"
# include "buffer.h"
# include "strerr.h"
# include "getln.h"
# include "cdb_make.h"
# include "stralloc.h"
# include "open.h"
# include "dns.h"

int fdcdb;
struct cdb_make cdb;
buffer b;
char bspace[1024];
static stralloc key;
static stralloc result;
static char* dottemp1;
static char* dottemp2;
static char tinydns_datafile[256];
static char tinydns_tempfile[256];

#endif

static char tinydns_textfile[256];
static LDAP* ldap_con;
static FILE* bindfile;
static FILE* tinyfile;
static FILE* ldifout;
static time_t time_now;
static int autoreverse;
static char* const* main_argv;
static int main_argc;


static void print_version(void)
{
	printf("ldap2dns, version %s\n", VERSION);
	printf("  Copyright 2000 by Jacob Rief <jacob.rief@tiscover.com>\n\n");
}


static void die_ldap(int err)
{
	fprintf(stderr, "Fatal error: %s\n", ldap_err2string(err));
	exit(1);
}


static struct
{
	char domainname[64];
	char zonemaster[64];
	char adminmailbox[64];
	unsigned long serial;
	unsigned long refresh;
	unsigned long retry;
	unsigned long expire;
	unsigned long minimum;
	int ttl;
	char timestamp[16];
} zone;

struct resourcerecord
{
	char cn[64];
	char dnsdomainname[64];
	char class[16];
	char type[16];
	char ipaddr[256][32];
	char cname[64];
	int ttl;
	char timestamp[16];
	int preference;
#if defined DRAFT_RFC
	char rr[1024];
	char aliasedobjectname[256];
	char macaddress[32];
#endif
};


static struct
{
	char searchbase[128];
	char binddn[128];
	char hostname[128];
	char password[128];
	int is_daemon;
	int update_iv;
	int port;
	unsigned int output;
	int verbose;
	char ldifname[128];
} options;


static void die_exit(const char* message)
{
	if (message)
		fprintf(stderr, "Fatal error: %s\n", message);
	else
		fprintf(stderr, "Fatal memory error\n");
	exit(1);
}


#if defined WITH_TINYDNS

static void rr_add(char *buf, unsigned int len)
{
	if (!stralloc_catb(&result, buf, len)) die_exit(0);
}

static void rr_addname(char *d)
{
	rr_add(d,dns_domain_length(d));
}

static void rr_start(char type[2], unsigned long ttl, char ttd[8])
{
	char buf[4];
	if (!stralloc_copyb(&result, type,2)) die_exit(0);
	rr_add("=",1);
	uint32_pack_big(buf, ttl);
	rr_add(buf,4);
	rr_add(ttd,8);
}

static void rr_finish(char *owner)
{
	if (byte_equal(owner,2,"\1*")) {
		owner += 2;
		result.s[2] = '*';
	}
	if (!stralloc_copyb(&key, owner, dns_domain_length(owner))) die_exit(0);
		case_lowerb(key.s, key.len);
	if (cdb_make_add(&cdb, key.s, key.len, result.s, result.len) == -1)
		die_exit("Unable to create 'data.tmp'");
}


#endif

static void set_datadir(void)
{
	char* ev = getenv("TINYDNSDIR");
	int len;

#if defined WITH_TINYDNS
	tinydns_datafile[0] = 0;
	tinydns_tempfile[0] = 0;
#endif
	tinydns_textfile[0] = 0;
	if (ev && (len = strlen(ev))<240) {
#if defined WITH_TINYDNS
		strncpy(tinydns_datafile, ev, 240);
		strncpy(tinydns_tempfile, ev, 240);
#endif
		strncpy(tinydns_textfile, ev, 240);
		if (ev[len-1]!='/') {
#if defined WITH_TINYDNS
			tinydns_datafile[len] = '/';
			tinydns_tempfile[len] = '/';
#endif
			tinydns_textfile[len] = '/';
		}
	}
#if defined WITH_TINYDNS
	strcat(tinydns_datafile, "data.cdb");
	strcat(tinydns_tempfile, "data.tmp");
#endif
	strcat(tinydns_textfile, "data");
}


static void print_usage(void)
{
	print_version();
	printf("usage: ldap2dns[d] [-D binddn] [-b searchbase] [-o 0|1|2|4] [-h host] [-p port] [-w password] [-L[filename]] [-u numsecs] [-v[v]] [-V]\n\n");
	printf("ldap2dns connects to an LDAP server reads the DNS information stored in objectclasses\n"
		"\t\tDNSzone and DNSrrset and writes a file to be used by tinydns or named.\n"
		"\t\tldap2dnsd starts as background-job and continouesly updates DNS information.\n");
	printf("options:\n");
	printf("    -D binddn\tUse the distinguished name binddn to bind to the LDAP directory\n");
	printf("    -w bindpasswd\tUse bindpasswd as the password for simple authentication\n");
	printf("    -b use searchbase as the starting point for the search instead of the default\n");
	printf("    -o 1|2|4\toutput format number or any binary or-ed combination. Defaults to 1\n");
	printf("\t1: generate a binary file named 'data.cdb' to be used directly by tinydns\n");
	printf("\t2: generate a text file named 'data' to be parsed by tinydns-data\n");
	printf("\t4: for each zone generate a file named '<zonename>.db' to be used by named\n");
	printf("    -L[filename] print output in LDIF format for reimport\n");
	printf("    -h host\thostname of LDAP server, defaults to localhost\n");
	printf("    -p port\tportnumber to connect to LDAP server, defaults to %d\n", LDAP_PORT);
	printf("    -u numsecs\tUpdate DNS data after numsecs. Defaults to %d if started as daemon.\n\t\t"
		"Important notice: data.cdb is rewritten only after DNSserial in DNSzone is increased.\n",
		UPDATE_INTERVALL);
	printf("    -v\t\trun in verbose mode\n");
	printf("    -vv\t\teven more verbose\n");
	printf("    -V\t\tprint version and exit\n\n");
}

static int parse_options()
{
	extern char* optarg;
	extern int optind, opterr, optopt;
	char buf[256], value[128];
	int c;
	FILE* ldap_conf;

	strcpy(options.searchbase, "");
	strcpy(options.hostname, "localhost");
	options.port = LDAP_PORT;
	if (ldap_conf = fopen(LDAP_CONF, "r")) {
		while(fgets(buf, 256, ldap_conf)!=0) {
			if (sscanf(buf, "BASE %128s", value)==1)
				strcpy(options.searchbase, value);
			if (sscanf(buf, "HOST %128s:%d", value, &c)==2) {
				strcpy(options.hostname, value);
				options.port = c;
			} else if (sscanf(buf, "HOST %128s", value)==1)
				strcpy(options.hostname, value);
			if (sscanf(buf, "PORT %d", &c)==1)
				options.port = c;
		}
		fclose(ldap_conf);
	}
	strcpy(options.binddn, "");
	options.output = 1;
	options.verbose = 0;
	options.ldifname[0] = '\0';
	c = strlen(main_argv[0]);
	if (strcmp(main_argv[0]+c-9, "ldap2dnsd")==0)
		options.is_daemon = 1;
	else
		options.is_daemon = 0;
	options.update_iv = 59;
	strcpy(options.password, "");
	while ( (c = getopt(main_argc, main_argv, "b:D:h:o:p:u:Vw:v::L::"))>0 ) {
		if (optarg && strlen(optarg)>127) {
			fprintf(stderr, "argument %s too long\n", optarg);
			continue;
		}
		switch (c) {
		    case 'b':
			strcpy(options.searchbase, optarg);
			break;
		    case 'u':
			if (sscanf(optarg, "%d", &options.update_iv)!=1)
				options.update_iv = UPDATE_INTERVALL;
			if (options.update_iv<=0) options.update_iv = 1;
			if (options.is_daemon==0) options.is_daemon = 2; /* foreground daemon */
			break;
		    case 'D':
			strcpy(options.binddn, optarg);
			break;
		    case 'h':
			strcpy(options.hostname, optarg);
			break;
		    case 'L':
			if (optarg==NULL)
				strcpy(options.ldifname, "-");
			else
				strcpy(options.ldifname, optarg);
			break;
		    case 'o':
			if (sscanf(optarg, "%d", &options.output)!=1)
				options.output = 0;
			break;
		    case 'p':
			if (sscanf(optarg, "%d", &options.port)!=1)
				options.port = LDAP_PORT;
			break;
		    case 'v':
			if (optarg && optarg[0]=='v')
				options.verbose = 3;
			else
				options.verbose = 1;
			break;
		    case 'V':
			print_version();
			exit(0);
		    case 'w':
			strcpy(options.password, optarg);
			break;
		    default:
			print_usage();
			exit(1);
		}
	}
}


static int expand_domainname(char target[64], const char* source, int slen)
{
	if (slen>64)
		return 0;
	if (source[slen-1]=='.') {
		strncpy(target, source, slen-1);
		target[slen-1] = '\0';
		return 1;
	}
	strncpy(target, source, slen);
	target[slen] = '\0';
	if (zone.domainname[0]) {
		if (zone.domainname[0]!='.')
			strcat(target, ".");
		strcat(target, zone.domainname);
		return 1;
	}
	return 0;
}


static int expand_reverse(char target[64], const char* source)
{
}


static void write_rr(struct resourcerecord* rr, int ipdx)
{
	char ip[4];
	char buf[4];

	if (strcasecmp(rr->class, "IN"))
		return;
	
#if defined WITH_TINYDNS
	if (options.output&1) {
		int dnsdn_len = strlen(rr->dnsdomainname);
		int cname_len = strlen(rr->cname);
		if (!dns_domain_fromdot(&dottemp1, rr->dnsdomainname, dnsdn_len)) die_exit(0);
		if (!dns_domain_fromdot(&dottemp2, rr->cname, cname_len)) die_exit(0);
	}
#endif

	if (strcasecmp(rr->type, "NS")==0) {
		if (tinyfile)
			fprintf(tinyfile, "&%s:%s:%s:%d:%s\n", rr->dnsdomainname, (ipdx>=0 ? rr->ipaddr[ipdx] : ""), rr->cname, rr->ttl, rr->timestamp);
		if (bindfile) {
			fprintf(bindfile, "%s.\tIN NS\t%s.\n", rr->dnsdomainname, rr->cname);
			if (ipdx>=0)
				fprintf(bindfile, "%s.\tIN A\t%s\n", rr->cname, rr->ipaddr[ipdx]);
		}
#if defined WITH_TINYDNS
		if (options.output&1) {
			rr_start(DNS_T_NS, rr->ttl, rr->timestamp);
			rr_addname(dottemp2);
			rr_finish(dottemp1);
			if (ipdx>=0 && ip4_scan(rr->ipaddr[ipdx], ip)) {
				rr_start(DNS_T_A, rr->ttl, rr->timestamp);
				rr_add(ip, 4);
				rr_finish(dottemp2);
			}
		}
#endif
	} else if (strcasecmp(rr->type, "MX")==0) {
		if (tinyfile)
			fprintf(tinyfile, "@%s:%s:%s:%d:%d:%s\n", rr->dnsdomainname, (ipdx>=0 ? rr->ipaddr[ipdx] : ""), rr->cname, rr->preference, rr->ttl, rr->timestamp);
		if (bindfile) {
			fprintf(bindfile, "%s.\tIN MX\t%d %s.\n", rr->dnsdomainname, rr->preference, rr->cname);
			if (ipdx>=0)
				fprintf(bindfile, "%s.\tIN A\t%s\n", rr->cname, rr->ipaddr[ipdx]);
		}
#if defined WITH_TINYDNS
		if (options.output&1) {
			rr_start(DNS_T_MX, rr->ttl, rr->timestamp);
			uint16_pack_big(buf, rr->preference);
			rr_add(buf, 2);
			rr_addname(dottemp2);
			rr_finish(dottemp1);
			if (ipdx>=0 && ip4_scan(rr->ipaddr[ipdx], ip)) {
				rr_start(DNS_T_A, rr->ttl, rr->timestamp);
				rr_add(ip, 4);
				rr_finish(dottemp2);
			}
		}
#endif
	} else if ( strcasecmp(rr->type, "A")==0) {
		if (tinyfile)
			fprintf(tinyfile, "%s%s:%s:%d:%s\n", (autoreverse ? "=" : "+"), rr->dnsdomainname, (ipdx>=0 ? rr->ipaddr[ipdx] : ""), rr->ttl, rr->timestamp);
		if (bindfile && ipdx>=0)
			fprintf(bindfile, "%s.\tIN A\t%s\n", rr->dnsdomainname, rr->ipaddr[ipdx]);
#if defined WITH_TINYDNS
		if (options.output&1) {
			char dptr[DNS_NAME4_DOMAIN];
			if (ipdx>=0 && ip4_scan(rr->ipaddr[ipdx], ip)) {
				rr_start(DNS_T_A, rr->ttl, rr->timestamp);
				rr_add(ip, 4);
				rr_finish(dottemp1);
			}
			if (autoreverse) {
				dns_name4_domain(dptr, ip);
				rr_start(DNS_T_PTR, rr->ttl, rr->timestamp);
				rr_addname(dottemp1);
				rr_finish(dptr);
			}
		}
#endif
	} else if (strcasecmp(rr->type, "PTR")==0) {
		int ip[4] = {0, 0, 0, 0};
		char buf[64];
		if (ipdx>0) {
			/* does not make to have more than one IPaddr for a PTR record */
			return;
		}
		if (ipdx==0 && sscanf(rr->ipaddr[0], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
			/* lazy user, used DNSipaddr for reverse lookup */
			sprintf(buf, "%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0]);
		} else {
			strcpy(buf, rr->dnsdomainname);
		}
		if (tinyfile)
			fprintf(tinyfile, "^%s:%s:%d:%s\n", buf, rr->cname, rr->ttl, rr->timestamp);
		if (bindfile)
			fprintf(bindfile, "%s.\tIN PTR\t%s.\n", buf, rr->cname);
#if defined WITH_TINYDNS
		if (options.output&1) {
			int dnsdn_len = strlen(buf);
			if (!dns_domain_fromdot(&dottemp1, buf, dnsdn_len)) die_exit(0);
			rr_start(DNS_T_PTR, rr->ttl, rr->timestamp);
			rr_addname(dottemp2);
			rr_finish(dottemp1);
		}
#endif
	} else if (strcasecmp(rr->type, "CNAME")==0) {
		if (tinyfile)
			fprintf(tinyfile, "C%s:%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
		if (bindfile)
			fprintf(bindfile, "%s.\tIN CNAME\t%s.\n", rr->dnsdomainname, rr->cname);
#if defined WITH_TINYDNS
		if (options.output&1) {
			rr_start(DNS_T_CNAME, rr->ttl, rr->timestamp);
			rr_addname(dottemp2);
			rr_finish(dottemp1);
		}
#endif
	} else if (strcasecmp(rr->type, "TXT")==0) {
		if (tinyfile)
			fprintf(tinyfile, "'%s:%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
		if (bindfile)
			fprintf(bindfile, "%s.\tIN TXT\t%s.\n", rr->dnsdomainname, rr->cname);
#if defined WITH_TINYDNS
		if (options.output&1) {
			rr_start(DNS_T_TXT, rr->ttl, rr->timestamp);
			rr_addname(dottemp2);
			rr_finish(dottemp1);
		}
#endif
	}
}


#if defined DRAFT_RFC
static void parse_rr(struct resourcerecord* rr)
{
	char word1[64];
	char word2[64];
	int ip[4];

	sscanf(rr->rr, "%16s %16s %64s %64s", rr->class, rr->type, word1, word2);
	if (strcasecmp(rr->type, "NS")==0) {
		if (sscanf(word1, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
			sprintf(rr->ipaddr[0], "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		} else {
			int len = strlen(word1);
			expand_domainname(rr->cname, word1, len);
		}
	} else if (strcasecmp(rr->type, "MX")==0) {
		if (sscanf(word1, "%d", &rr->preference)!=1)
			rr->preference = 0;
		if (sscanf(word2, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
			sprintf(rr->ipaddr[0], "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		} else {
			int len = strlen(word2);
			expand_domainname(rr->cname, word2, len);
		}
	} else if (strcasecmp(rr->type, "A")==0) {
		if (sscanf(word1, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4)
			sprintf(rr->ipaddr[0], "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		else
			rr->ipaddr[0][0] = '\0';
	} else if (strcasecmp(rr->type, "PTR")==0) {
		expand_reverse(rr->dnsdomainname, word1);
	} else if (strcasecmp(rr->type, "CNAME")==0) {
		int len = strlen(word1);
		expand_reverse(rr->cname, word1);
	} else if (strcasecmp(rr->type, "TXT")==0) {
		strncpy(rr->cname, word1, 64);
	}
}
#endif


static void read_resourcerecords(char* dn)
{
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ldaperr;

	if ( (ldaperr = ldap_search_s(ldap_con, dn, LDAP_SCOPE_ONELEVEL, "objectclass=DNSrrset", NULL, 0, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr;
		char* dn = ldap_get_dn(ldap_con, m);
		struct resourcerecord rr;
		int ipaddresses = 0;

		if (options.ldifname[0])
			fprintf(ldifout, "dn: %s\n", dn);
		rr.cn[0] = '\0';
		strncpy(rr.dnsdomainname, zone.domainname, 64);
		strcpy(rr.class, "IN");
		rr.type[0] = '\0';
		rr.cname[0] = '\0';
		rr.ttl = time_now;
		rr.timestamp[0] = '\0';
		rr.preference = 10;
#if defined DRAFT_RFC
		rr.aliasedobjectname[0] = '\0';
		rr.rr[0] = '\0';
#endif
		for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
			int len = strlen(attr);
			struct berval** bvals;
			char* dnsnname = "";

			if ( (bvals = ldap_get_values_len(ldap_con, m, attr))!=NULL ) {
				if (bvals[0] && bvals[0]->bv_len>0) {
					if (strcasecmp(attr, "objectclass")==0) {
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "cn")==0) {
						strncpy(rr.cn, bvals[0]->bv_val, 64);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.cn);
					} else if (strcasecmp(attr, "DNSdomainname")==0) {
						if (!expand_domainname(rr.dnsdomainname, bvals[0]->bv_val, bvals[0]->bv_len))
							rr.dnsdomainname[0] = '\0';;
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSclass")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", &rr.class)!=1)
							rr.class[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.class);
					} else if (strcasecmp(attr, "DNStype")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", &rr.type)!=1)
							rr.type[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.type);
					} else if (strcasecmp(attr, "DNSipaddr")==0) {
						int ip[4];
						for (ipaddresses = 0; bvals[ipaddresses] && ipaddresses<256; ipaddresses++) {
							rr.ipaddr[ipaddresses][0] = '\0';
							if (sscanf(bvals[ipaddresses]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4)
								sprintf(rr.ipaddr[ipaddresses], "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
							if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, rr.ipaddr[ipaddresses]);
						}
					} else if (strcasecmp(attr, "DNScname")==0) {
						if (!expand_domainname(rr.cname, bvals[0]->bv_val, bvals[0]->bv_len))
							rr.cname[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSttl")==0) {
						if (sscanf(bvals[0]->bv_val, "%d", &rr.ttl)!=1)
							rr.ttl = time_now;
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, rr.ttl);
					} else if (strcasecmp(attr, "DNStimestamp")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", &rr.timestamp)!=1)
							rr.timestamp[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.timestamp);
					} else if (strcasecmp(attr, "DNSpreference")==0) {
						if (sscanf(bvals[0]->bv_val, "%d", &rr.preference)!=1)
							rr.preference = 10;
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					}
#if defined DRAFT_RFC
					else if (strcasecmp(attr, "DNSrr")==0) {
						strncpy(rr.rr, bvals[0]->bv_val, 1024);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.rr);
					} else if (strcasecmp(attr, "DNSaliasedobjectname")==0) {
						if (sscanf(bvals[0]->bv_val, "%256s", rr.aliasedobjectname)!=1)
							rr.aliasedobjectname[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.aliasedobjectname);
					} else if (strcasecmp(attr, "DNSmacaddress")==0) {
					}
#endif
				}
				ldap_value_free_len(bvals);
			}
		}
#if defined DRAFT_RFC
		if (rr.rr[0]) {
			parse_rr(&rr);
		}
#endif
		do {
			ipaddresses--;
			write_rr(&rr, ipaddresses);
		} while (ipaddresses>0);
#if defined DRAFT_RFC
		if (rr.aliasedobjectname[0])
			read_resourcerecords(rr.aliasedobjectname);
#endif
		if (options.ldifname[0])
			fprintf(ldifout, "\n");
		if (options.verbose&2)
			printf("\trr: %s %s %s\n", rr.class, rr.type, rr.dnsdomainname);
		free(dn);
	}
	ldap_msgfree(res);
}


static void write_zone(void)
{
	int len;
	char soa[20];

	if (tinyfile) {
		fprintf(tinyfile, "Z%s:%s:%s:%d:%d:%d:%d:%d:%d:%s\n", zone.domainname,
		    zone.zonemaster, zone.adminmailbox, zone.serial, zone.refresh, zone.retry,
		    zone.expire, zone.minimum, zone.ttl, zone.timestamp);
	}
	
	if (bindfile) {
		fprintf(bindfile, "; Automatically generated by ldap2dns - DO NOT EDIT!\n");
		fprintf(bindfile, "%s. IN SOA %s. %s. ", zone.domainname, zone.zonemaster, zone.adminmailbox);
		fprintf(bindfile, "(\n\t%d\t; Serial\n\t%d\t; Refresh\n\t%d\t; Retry\n\t%d\t; Expire\n\t%d )\t; Minimum\n", zone.serial, zone.refresh, zone.retry, zone.expire, zone.minimum); 
	}

#if defined WITH_TINYDNS
	if (options.output&1) {
		byte_zero(zone.timestamp, 8);
		len = strlen(zone.domainname);
		if (!dns_domain_fromdot(&dottemp1, zone.domainname, len)) die_exit(0);
		uint32_pack_big(soa, zone.serial);
		uint32_pack_big(soa+4, zone.refresh);
		uint32_pack_big(soa+8, zone.retry);
		uint32_pack_big(soa+12, zone.expire);
		uint32_pack_big(soa+16, zone.minimum);
		rr_start(DNS_T_SOA, zone.ttl, zone.timestamp);
		len = strlen(zone.zonemaster);
		if (!dns_domain_fromdot(&dottemp2, zone.zonemaster, len)) die_exit(0);
		rr_addname(dottemp2);
		len = strlen(zone.adminmailbox);
		if (!dns_domain_fromdot(&dottemp2, zone.adminmailbox, len)) die_exit(0);
		rr_addname(dottemp2);
		rr_add(soa, 20);
		rr_finish(dottemp1);
	}
#endif
	if (options.ldifname[0])
		fprintf(ldifout, "\n");
}


static void calc_checksum(int* num, int* sum)
{
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ldaperr;
	char* attr_list[2] = { "DNSserial", NULL };

	*num = *sum = 0;
	if ( ldaperr = ldap_search_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSzone", attr_list, 0, &res)!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr = ldap_first_attribute(ldap_con, m, &ber);
		if (attr) {
                        struct berval** bvals = ldap_get_values_len(ldap_con, m, attr);
                        if (bvals!=NULL) {
				unsigned tmp;
				if (sscanf(bvals[0]->bv_val, "%u", &tmp)==1) {
					(*num)++;
					*sum += tmp;
				}	
				ldap_value_free_len(bvals);
			}
		}
		ber_free(ber, 0);
	}
	ldap_msgfree(res);
}


static void read_dnszones(void)
{
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ldaperr;

	if (tinyfile)
		fprintf(tinyfile, "# Automatically generated by ldap2dns - DO NOT EDIT!\n");
	if ( (ldaperr = ldap_search_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSzone", NULL, 0, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr;
		char* dn;
		int i, zonenames = 0;
		char zdn[256][64];
		char ldif0;

		zone.serial = time_now;
		zone.refresh = 10800;
		zone.retry = 3600;
		zone.expire = 604800;
		zone.minimum = 86400;
		zone.ttl = time_now;
		zone.timestamp[0] = '\0';
		dn = ldap_get_dn(ldap_con, m);
		if (options.ldifname[0])
			fprintf(ldifout, "dn: %s\n", dn);
		for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
			struct berval** bvals = ldap_get_values_len(ldap_con, m, attr);
			if (bvals!=NULL) {
				if (bvals[0] && bvals[0]->bv_len>0) {
					if (strcasecmp(attr, "objectclass")==0
					    || strcasecmp(attr, "DNSclass")==0
					    || strcasecmp(attr, "DNStype")==0
					    || strcasecmp(attr, "cn")==0) {
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSzonename")==0) {
						for (zonenames = 0; bvals[zonenames] && zonenames<256; zonenames++) {
							if (sscanf(bvals[zonenames]->bv_val, "%64s", &zdn[zonenames])!=1)
								zdn[zonenames][0] = '\0';
							if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, zdn[zonenames]);
						}
					} else if (strcasecmp(attr, "DNSserial")==0) {
						sscanf(bvals[0]->bv_val, "%u", &zone.serial);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.serial);
					} else if (strcasecmp(attr, "DNSrefresh")==0) {
						sscanf(bvals[0]->bv_val, "%u", &zone.refresh);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.refresh);
					} else if (strcasecmp(attr, "DNSretry")==0) {
						sscanf(bvals[0]->bv_val, "%u", &zone.retry);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.retry);
					} else if (strcasecmp(attr, "DNSexpire")==0) {
						sscanf(bvals[0]->bv_val, "%u", &zone.expire);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.expire);
					} else if (strcasecmp(attr, "DNSminimum")==0) {
						sscanf(bvals[0]->bv_val, "%u", &zone.minimum);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.minimum);
					} else if (strcasecmp(attr, "DNSadminmailbox")==0) {
						sscanf(bvals[0]->bv_val, "%64s", zone.adminmailbox);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.adminmailbox);
					} else if (strcasecmp(attr, "DNSzonemaster")==0) {
						sscanf(bvals[0]->bv_val, "%64s", zone.zonemaster);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.zonemaster);
					} else if (strcasecmp(attr, "DNSttl")==0) {
						if (sscanf(bvals[0]->bv_val, "%d", &zone.ttl)!=1)
							zone.ttl = time_now;
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %d\n", attr, zone.ttl);
					} else if (strcasecmp(attr, "DNStimestamp")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", &zone.timestamp)!=1)
							zone.timestamp[0] = '\0';
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.timestamp);
					}
				}
				ldap_value_free_len(bvals);
			}
		}
		ldif0 = options.ldifname[0];
		for (i = 0; i<zonenames; i++) {
			strncpy(zone.domainname, zdn[i], 64);
			if (i>0)
				options.ldifname[0] = '\0';
			if (options.verbose&1)
				printf("zonename: %s\n", zone.domainname);
			if (options.output&4) {
				char bindfilename[128];
				sprintf(bindfilename, "%s.db", zone.domainname);
				if ( !(bindfile = fopen(bindfilename, "w")) )
					die_exit("Unable to open db-file for writing");
			}
			write_zone();
			read_resourcerecords(dn);
			if (bindfile)
				fclose(bindfile);
			if (options.verbose&2)
				printf("\n");
			if (options.ldifname[0])
				fprintf(ldifout, "\n");
		}
		options.ldifname[0] = ldif0;
		free(dn);
	}
	ldap_msgfree(res);
}


int main(int argc, char** argv)
{
	int soa_numzones;
	int soa_checksum;

	umask(022);
	main_argc = argc;
	main_argv = argv;
	parse_options();
	if (options.is_daemon) {
		if (options.is_daemon==1 && fork())
			exit(0);
		/* lowest priority */
		nice(19);
	}
	set_datadir();
	for (;;) {
		int ldaperr;
		if ( !(ldap_con = ldap_init(options.hostname, options.port)) )
			die_exit("Unable to initialize connection to LDAP server");
		ldaperr = ldap_simple_bind_s(ldap_con, options.binddn, options.password);
		if (ldaperr!=LDAP_SUCCESS) {
			fprintf(stderr, "Warning - Could not connect to LDAP server %s:%d as '%s'\n", options.hostname, options.port, options.binddn);
			sleep(options.update_iv);
			continue;
		}
		if (options.is_daemon) {
			int num, sum;
			calc_checksum(&num, &sum);
			if (num!=soa_numzones || sum!=soa_checksum) {
				if (options.verbose&1)
					printf("DNSserial has changed in LDAP zone(s)\n");
				soa_numzones = num;
				soa_checksum = sum;
			} else {
				goto skip;
			}
		}
#if defined WITH_TINYDNS
		if (options.output&1) {
			fdcdb = open_trunc(tinydns_tempfile);
			if (fdcdb == -1) die_exit("Unable to create 'data.tmp'");
			if (cdb_make_start(&cdb, fdcdb) == -1) die_exit("Unable to create 'data.tmp'");
		}
#endif
		if (options.ldifname[0]) {
			if (options.ldifname[0]=='-')
				ldifout = stdout;
			else
				ldifout = fopen(options.ldifname, "w");
			if (!ldifout)
				die_exit("Unable to open LDIF-file for writing");
		}
		time(&time_now);
		if ( options.output&2 && !(tinyfile = fopen(tinydns_textfile, "w")) )
			die_exit("Unable to open file 'data' for writing");
		read_dnszones();
		if (tinyfile)
			fclose(tinyfile);
		if (options.ldifname[0] && ldifout)
			fclose(ldifout);
#if defined WITH_TINYDNS
		if (options.output&1) {
			if (cdb_make_finish(&cdb)==-1 || fsync(fdcdb)==-1 || close(fdcdb)==-1)
				die_exit("Unable to create 'data.tmp'");
			if (rename(tinydns_tempfile, tinydns_datafile)==-1)
				die_exit("Unable to move 'data.tmp' to 'data.cdb'");
		}
#endif
	    skip:
		if ( (ldaperr = ldap_unbind_s(ldap_con))!=LDAP_SUCCESS )
			die_ldap(ldaperr);
		if (options.is_daemon==0)
			break;
		sleep(options.update_iv);
	}
	return 0;
}

