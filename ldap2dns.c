/*
 * Create data from an LDAP directory service to be used for tinydns
 * $Id: ldap2dns.c,v 1.26 2001/02/27 10:08:31 jrief Exp $
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
#define OUTPUT_DATA 1
#define OUTPUT_DB 2

static char tinydns_textfile[256];
static char tinydns_texttemp[256];
static LDAP* ldap_con;
static FILE* namedmaster;
static FILE* namedzone;
static FILE* tinyfile;
static FILE* ldifout;
static time_t time_now;
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
	char class[16];
	char adminmailbox[64];
	unsigned long serial;
	unsigned long refresh;
	unsigned long retry;
	unsigned long expire;
	unsigned long minimum;
	char timestamp[20];
	int ttl;
} zone;

struct resourcerecord
{
	char cn[64];
	char dnsdomainname[64];
	char class[16];
	char type[16];
	char ipaddr[256][32];
	char cipaddr[32];
	char cname[64];
	char timestamp[20];
	int ttl;
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
	char exec_command[128];
} options;


static void die_exit(const char* message)
{
	if (message)
		fprintf(stderr, "Fatal error: %s\n", message);
	else
		fprintf(stderr, "Fatal memory error\n");
	exit(1);
}


static void set_datadir(void)
{
	char* ev = getenv("TINYDNSDIR");
	int len;

	tinydns_textfile[0] = '\0';
	tinydns_texttemp[0] = '\0';
	if (ev && (len = strlen(ev))<240) {
		strncpy(tinydns_textfile, ev, 240);
		strncpy(tinydns_texttemp, ev, 240);
		if (ev[len-1]!='/') {
			tinydns_textfile[len] = '/';
			tinydns_texttemp[len] = '/';
		}
	}
	strcat(tinydns_textfile, "data");
	strcat(tinydns_texttemp, "data.temp");
}


static void print_usage(void)
{
	print_version();
	printf("usage: ldap2dns[d] [-D binddn] [-b searchbase] [-o data|db] [-h host] [-p port] [-w password] [-L[filename]] [-u numsecs] [-v[v]] [-V]\n\n");
	printf("ldap2dns connects to an LDAP server reads the DNS information stored in objectclasses\n"
		"\t\tDNSzone and DNSrrset and writes a file to be used by tinydns or named.\n"
		"\t\tldap2dnsd starts as background-job and continouesly updates DNS information.\n");
	printf("options:\n");
	printf("    -D binddn\tUse the distinguished name binddn to bind to the LDAP directory\n");
	printf("    -w bindpasswd\tUse bindpasswd as the password for simple authentication\n");
	printf("    -b Use searchbase as the starting point for the search instead of the default\n");
	printf("    -o data\tGenerate a \"data\" file to be processed by tinydns-data\n");
	printf("    -o db\tFor each zone generate a \"<zonename>.db\" file to be used by named\n");
	printf("    -L[filename] Print output in LDIF format for reimport\n");
	printf("    -h host\tHostname of LDAP server, defaults to localhost\n");
	printf("    -p port\tPortnumber to connect to LDAP server, defaults to %d\n", LDAP_PORT);
	printf("    -u numsecs\tUpdate DNS data after numsecs. Defaults to %d if started as daemon.\n\t\t"
		"Important notice: data.cdb is rewritten only after DNSserial in DNSzone is increased.\n",
		UPDATE_INTERVALL);
	printf("    -e \"exec-cmd\" This command is executed after ldap2dns regenerated its data files\n");
	printf("    -v\t\trun in verbose mode\n");
	printf("    -vv\t\teven more verbose\n");
	printf("    -V\t\tprint version and exit\n\n");
}

static int parse_options()
{
	extern char* optarg;
	extern int optind, opterr, optopt;
	char buf[256], value[128];
	int len;
	FILE* ldap_conf;
	char* ev;

	strcpy(options.searchbase, "");
	strcpy(options.hostname, "localhost");
	options.port = LDAP_PORT;
	if (ldap_conf = fopen(LDAP_CONF, "r")) {
		while(fgets(buf, 256, ldap_conf)!=0) {
			if (sscanf(buf, "BASE %128s", value)==1)
				strcpy(options.searchbase, value);
			if (sscanf(buf, "HOST %128s:%d", value, &len)==2) {
				strcpy(options.hostname, value);
				options.port = len;
			} else if (sscanf(buf, "HOST %128s", value)==1)
				strcpy(options.hostname, value);
			if (sscanf(buf, "PORT %d", &len)==1)
				options.port = len;
		}
		fclose(ldap_conf);
	}
	strcpy(options.binddn, "");
	len = strlen(main_argv[0]);
	if (strcmp(main_argv[0]+len-9, "ldap2dnsd")==0) {
		options.is_daemon = 1;
		options.update_iv = UPDATE_INTERVALL;
	} else {
		options.is_daemon = 0;
		options.update_iv = 0;
	}
	ev = getenv("LDAP2DNS_UPDATE");
	if (ev && sscanf(ev, "%d", &len)==1 && len>0)
		options.update_iv = len;
	options.output = 0;
	ev = getenv("LDAP2DNS_OUTPUT");
	if (ev) {
		if (strcmp(ev, "data")==0)
			options.output = OUTPUT_DATA;
		else if (strcmp(ev, "db")==0)
			options.output = OUTPUT_DB;
	}
	options.verbose = 0;
	options.ldifname[0] = '\0';
	strcpy(options.password, "");
	strcpy(options.exec_command, "");
	while ( (len = getopt(main_argc, main_argv, "b:D:e:h:o:p:u:Vw:v::L::"))>0 ) {
		if (optarg && strlen(optarg)>127) {
			fprintf(stderr, "argument %s too long\n", optarg);
			continue;
		}
		switch (len) {
		    case 'b':
			strcpy(options.searchbase, optarg);
			break;
		    case 'u':
			if (sscanf(optarg, "%d", &options.update_iv)!=1)
				options.update_iv = UPDATE_INTERVALL;
			if (options.update_iv<=0) options.update_iv = 1;
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
			if (strcmp(optarg, "data")==0)
				options.output |= OUTPUT_DATA;
			else if (strcmp(optarg, "db")==0)
				options.output |= OUTPUT_DB;
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
		    case 'e':
			strcpy(options.exec_command, optarg);
			break;
		    default:
			print_usage();
			exit(1);
		}
	}
	if (options.is_daemon==0 && options.update_iv>0)
		options.is_daemon = 2; /* foreground daemon */
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


static void write_rr(struct resourcerecord* rr, int ipdx, int znix)
{
	char ip[4];
	char buf[4];

	if (strcasecmp(rr->class, "IN"))
		return;
	if (strcasecmp(rr->type, "NS")==0) {
		if (tinyfile) {
			if (znix==0) {
				if (ipdx<=0 && rr->cipaddr[0]) {
					fprintf(tinyfile, "&%s::%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
					if (rr->cname[0])
						fprintf(tinyfile, "=%s:%s:%d:%s\n", rr->cname, rr->cipaddr, rr->ttl, rr->timestamp);
					if (ipdx==0)
						fprintf(tinyfile, "+%s:%s:%d:%s\n", rr->cname, rr->ipaddr[0], rr->ttl, rr->timestamp);
				} else if (ipdx<0)
					fprintf(tinyfile, "&%s::%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
				else if (ipdx==0)
					fprintf(tinyfile, "&%s:%s:%s:%d:%s\n", rr->dnsdomainname, rr->ipaddr[0], rr->cname, rr->ttl, rr->timestamp);
				else if (ipdx>0 && rr->cname[0])
					fprintf(tinyfile, "+%s:%s:%d:%s\n", rr->cname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp);
			} else if (ipdx<=0) {
				fprintf(tinyfile, "&%s::%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
			}
		}
		if (namedzone) {
			fprintf(namedzone, "%s.\tIN NS\t%s.\n", rr->dnsdomainname, rr->cname);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\tIN A\t%s\n", rr->cname, rr->ipaddr[ipdx]);
		}
	} else if (strcasecmp(rr->type, "MX")==0) {
		if (tinyfile) {
			if (znix==0) {
				if (ipdx<=0 && rr->cipaddr[0]) {
					fprintf(tinyfile, "@%s::%s:%d:%d:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp);
					if (rr->cname[0])
						fprintf(tinyfile, "=%s:%s:%d:%s\n", rr->cname, rr->cipaddr, rr->ttl, rr->timestamp);
					if (ipdx==0)
						fprintf(tinyfile, "+%s:%s:%d:%s\n", rr->cname, rr->ipaddr[0], rr->ttl, rr->timestamp);
				} else if (ipdx<0)
					fprintf(tinyfile, "@%s::%s:%d:%d:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp);
				else if (ipdx==0)
					fprintf(tinyfile, "@%s:%s:%s:%d:%d:%s\n", rr->dnsdomainname, rr->ipaddr[0], rr->cname, rr->preference, rr->ttl, rr->timestamp);
				else if (ipdx>0 && rr->cname[0])
					fprintf(tinyfile, "+%s:%s:%d:%s\n", rr->cname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp);
			} else if (ipdx<=0) {
				fprintf(tinyfile, "@%s::%s:%d:%d:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp);
			}
		}
		if (namedzone) {
			fprintf(namedzone, "%s.\tIN MX\t%d %s.\n", rr->dnsdomainname, rr->preference, rr->cname);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\tIN A\t%s\n", rr->cname, rr->ipaddr[ipdx]);
		}
	} else if ( strcasecmp(rr->type, "A")==0) {
		if (tinyfile) {
			if (ipdx<=0 && rr->cipaddr[0])
				fprintf(tinyfile, "%s%s:%s:%d:%s\n", (znix==0 ? "=" : "+"), rr->dnsdomainname, rr->cipaddr, rr->ttl, rr->timestamp);
			if (ipdx>=0)
				fprintf(tinyfile, "+%s:%s:%d:%s\n", rr->dnsdomainname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp);
		}
		if (namedzone) {
			if (ipdx<=0 && rr->cipaddr[0])
				fprintf(namedzone, "%s.\tIN A\t%s\n", rr->dnsdomainname, rr->cipaddr);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\tIN A\t%s\n", rr->dnsdomainname, rr->ipaddr[ipdx]);
		}
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
		if (namedzone)
			fprintf(namedzone, "%s.\tIN PTR\t%s.\n", buf, rr->cname);
	} else if (strcasecmp(rr->type, "CNAME")==0) {
		if (tinyfile)
			fprintf(tinyfile, "C%s:%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
		if (namedzone)
			fprintf(namedzone, "%s.\tIN CNAME\t%s.\n", rr->dnsdomainname, rr->cname);
	} else if (strcasecmp(rr->type, "TXT")==0) {
		if (tinyfile)
			fprintf(tinyfile, "'%s:%s:%d:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp);
		if (namedzone)
			fprintf(namedzone, "%s.\tIN TXT\t%s.\n", rr->dnsdomainname, rr->cname);
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


static void read_resourcerecords(char* dn, int znix)
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
		strncpy(rr.class, "IN", 3);
		rr.type[0] = '\0';
		rr.cname[0] = '\0';
		rr.cipaddr[0] = '\0';
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
					} else if (strcasecmp(attr, "DNScipaddr")==0) {
						int ip[4];
						if (sscanf(bvals[0]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4)
							sprintf(rr.cipaddr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.cipaddr);
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
			write_rr(&rr, ipaddresses, znix);
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
	if (namedmaster) {
		fprintf(namedmaster, "zone \"%s\" %s {\n\ttype master;\n\tfile \"%s.db\";\n};\n",
		    zone.domainname, zone.class, zone.domainname);
	}
	if (namedzone) {
		fprintf(namedzone, "# Automatically generated by ldap2dns - DO NOT EDIT!\n");
		fprintf(namedzone, "$TTL %d\n", (zone.ttl>0) ? zone.ttl : 3600);
		fprintf(namedzone, "%s. IN SOA ", zone.domainname);
		len = strlen(zone.zonemaster);
		fprintf(namedzone, (zone.zonemaster[len-1]=='.') ? "%s " : "%s. ", zone.zonemaster);
		len = strlen(zone.adminmailbox);
		fprintf(namedzone, (zone.adminmailbox[len-1]=='.') ? "%s " : "%s. ", zone.adminmailbox);
		fprintf(namedzone, "(\n\t%d\t; Serial\n\t%d\t; Refresh\n\t%d\t; Retry\n\t%d\t; Expire\n\t%d )\t; Minimum\n", zone.serial, zone.refresh, zone.retry, zone.expire, zone.minimum); 
	}
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
	if (namedmaster)
		fprintf(namedmaster, "# Automatically generated by ldap2dns - DO NOT EDIT!\n");
	if ( (ldaperr = ldap_search_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSzone", NULL, 0, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr;
		char* dn;
		int i, zonenames = 0;
		char zdn[256][64];
		char ldif0;

		strncpy(zone.class, "IN", 3);
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
			if (options.output&OUTPUT_DB) {
				char namedzonename[128];
				sprintf(namedzonename, "%s.db", zone.domainname);
				if ( !(namedzone = fopen(namedzonename, "w")) )
					die_exit("Unable to open db-file for writing");
			}
			write_zone();
			read_resourcerecords(dn, i);
			if (namedzone)
				fclose(namedzone);
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
		ldap_con = ldap_init(options.hostname, options.port);
		ldaperr = ldap_con && ldap_simple_bind_s(ldap_con, options.binddn, options.password);
		if (ldaperr!=LDAP_SUCCESS) {
			fprintf(stderr, "Warning - Could not connect to LDAP server %s:%d as '%s'\n", options.hostname, options.port, options.binddn);
			if (options.is_daemon==0)
				break;
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
		if (options.ldifname[0]) {
			if (options.ldifname[0]=='-')
				ldifout = stdout;
			else
				ldifout = fopen(options.ldifname, "w");
			if (!ldifout)
				die_exit("Unable to open LDIF-file for writing");
		}
		time(&time_now);
		if ( options.output&OUTPUT_DATA && !(tinyfile = fopen(tinydns_texttemp, "w")) )
			die_exit("Unable to open file 'data.temp' for writing");
		if ( options.output&OUTPUT_DB && !(namedmaster = fopen("named.zones", "w")) )
			die_exit("Unable to open file 'named.zones' for writing");
		read_dnszones();
		if (namedmaster)
			fclose(namedmaster);
		if (tinyfile) {
			fclose(tinyfile);
			if (soa_numzones==0 || soa_checksum==0)
				break;
			if (rename(tinydns_texttemp, tinydns_textfile)==-1)
				die_exit("Unable to move 'data.temp' to 'data'");
		}
		if (options.ldifname[0] && ldifout)
			fclose(ldifout);
		if (options.exec_command[0])
			system(options.exec_command);
	    skip:
		if ( (ldaperr = ldap_unbind_s(ldap_con))!=LDAP_SUCCESS )
			die_ldap(ldaperr);
		if (options.is_daemon==0)
			break;
		sleep(options.update_iv);
	}
	return 0;
}

