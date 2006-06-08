/*
 * Create data from an LDAP directory service to be used for tinydns
 * $Id$
 * Copyright 2005-2006 by Ben Klang <ben@alkaloid.net>
 * Copyright 2000-2005 by Jacob Rief <jacob.rief@tiscover.com>
 * License: GPL version 2. See http://www.fsf.org for details
 */

#include <lber.h>
#include <ldap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#define UPDATE_INTERVAL 59
#define LDAP_CONF "/etc/ldap.conf"
#define OUTPUT_DATA 1
#define OUTPUT_DB 2
#define MAXHOSTS 10

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
	printf("\n");
	printf("ldap2dns version %s\n", VERSION);
	printf("\n");
	printf("  Copyright 2005-2006 by Ben Klang <ben@alkaloid.net>\n");
	printf("  Copyright 2000-2005 by Jacob Rief <jacob.rief@tiscover.com>\n");
	printf("\n");
	printf("  Released under the terms of the GPL.\n");
	printf("  http://projects.alkaloid.net\n");
	printf("\n");
}


static void die_ldap(int err)
{
	fprintf(stderr, "Fatal LDAP error: %s\n", ldap_err2string(err));
	exit(1);
}


static struct
{
	char domainname[64];
	char zonemaster[64];
	char class[16];
	char adminmailbox[64];
	char serial[12];
	char refresh[12];
	char retry[12];
	char expire[12];
	char minimum[12];
	char ttl[12];
	char timestamp[20];
	char location[2];
} zone;

static struct
{
	char locname[3];
	char member[256][16];
} loc_rec;

struct resourcerecord
{
	char cn[64];
	char dnsdomainname[64];
	char class[16];
	char type[16];
	char ipaddr[256][32];
	char cipaddr[32];
	char cname[64];
	char ttl[12];
	char timestamp[20];
	char preference[12];
	char location[2];
#if defined DRAFT_RFC
	char rr[1024];
	char aliasedobjectname[256];
	char macaddress[32];
#endif
	int dnssrvpriority;
	int dnssrvweight;
	int dnssrvport;
};


static struct
{
	char searchbase[128];
	char binddn[128];
	char hostname[MAXHOSTS][128];
	char urildap[MAXHOSTS][128];
	unsigned short port[MAXHOSTS];
	char password[128];
	int usedhosts;
	int useduris;
	int is_daemon;
	unsigned int update_iv;
	unsigned int output;
	int verbose;
	char ldifname[128];
	char exec_command[128];
	int use_tls[MAXHOSTS];
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
	printf("usage: ldap2dns[d] [-o data|db] [-h host] [-p port] \\\n");
	printf("\t\t[-H hostURI] [-w password] [-L[filename]] [-u numsecs] \\\n");
	printf("\t\t[-D binddn] [-b searchbase] [-v[v]] [-V]\n");
	printf("\n");
	printf(" *\tldap2dns formats DNS information from an LDAP server for tinydns or BIND\n");
	printf(" *\tldap2dnsd runs backgrounded refreshing the data on regular intervals\n");
	printf("\n");
	printf("options:\n");
	printf("  -D binddn\tUse the distinguished name binddn to bind to the LDAP directory\n");
	printf("  -w bindpasswd\tUse bindpasswd as the password for simple authentication\n");
	printf("  -b\t\tSearch base to use instead of default\n");
	printf("  -o data\tGenerate a tinydns compatible \"data\" file\n");
	printf("  -o db\t\tGenerate a BIND compatible zone files\n");
	printf("  -L [filename]\tPrint output in LDIF format for reimport\n");
	printf("  -h host\tHostname of LDAP server, defaults to localhost\n");
	printf("  -p port\tPort number to connect to LDAP server, defaults to %d\n", LDAP_PORT);
	printf("  -H hostURI\tURI (ldap://hostname or ldaps://hostname of LDAP server\n");
	printf("  -u numsecs\tUpdate DNS data after numsecs. Defaults to %d. Daemon mode only\n\t\t", UPDATE_INTERVAL);
	printf("\n");
	printf("  -e \"exec-cmd\"\tCommand to execute after data is generated\n");
	printf("  -v\t\trun in verbose mode, repeat for more verbosity\n");
	printf("  -V\t\tprint version and exit\n\n");
	printf("\n");
	printf("Note: Zone data are only updated after zone serials increment.\n");
}

static void parse_hosts(char* buf)
{
        int i, k;
        unsigned short port;
        char value[128], rest[512];

        options.usedhosts = 0;
        options.useduris = 0;
        for (i = 0; i<MAXHOSTS; i++) {
		if (!strncasecmp(buf, "ldaps://", 8) || !strncasecmp(buf, "ldap://", 7)) {
			// LDAP-URI is given/found, at the moment only the standard-ports 389 and 636 are supported
			if (!strncasecmp(buf, "ldap://", 7))
				options.use_tls[i] = 1;
			if ((k = sscanf(buf, "%128s %512[A-Za-z0-9 .:/_+-]", value, rest))>=1) {
                strncpy(options.urildap[i], value, sizeof(options.urildap[i]));
                options.urildap[i][ sizeof(options.urildap[i]) -1 ] = '\0';

				options.useduris++;
				if (k==1)
					break;
				buf = rest;
			} else break;
		} else if ((k = sscanf(buf, "%128s:%hd %512[A-Za-z0-9 .:_+-]", value, &port, rest))>=2) {
                        strcpy(options.hostname[i], value);
                        options.port[i] = port;
                        options.usedhosts++;
                        if (k==2)
                                break;
                        buf = rest;
                } else if ((k = sscanf(buf, "%128s %512[A-Za-z0-9 .:_+-]", value, rest))>=1) {
                        strcpy(options.hostname[i], value);
                        options.port[i] = LDAP_PORT;
                        options.usedhosts++;
                        if (k==1)
                                break;
                        buf = rest;
                } else break;
        }
}

static int parse_options()
{
	extern char* optarg;
	extern int optind, opterr, optopt;
	char buf[256], value[128];
	int len;
	FILE* ldap_conf,*fp;
	char* ev;

	strcpy(options.searchbase, "");
	strcpy(options.hostname[0], "localhost");
	options.port[0] = LDAP_PORT;
	if (ldap_conf = fopen(LDAP_CONF, "r")) {
		while(fgets(buf, 256, ldap_conf)!=0) {
			int i;
			if (sscanf(buf, "BASE %128s", value)==1){
				strncpy(options.searchbase, value, sizeof(options.searchbase));
				options.searchbase[sizeof(options.searchbase) -1] = '\0';
			}
			if (sscanf(buf, "URI %512[A-Za-z0-9 .:/_+-]", value)==1)
				parse_hosts(value);
			if (sscanf(buf, "HOST %512[A-Za-z0-9 .:_+-]", value)==1)
				parse_hosts(value);
			if (sscanf(buf, "PORT %hd", &len)==1)
				for (i = 0; i<MAXHOSTS; i++)
					options.port[i] = len;
			if (sscanf(buf, "BINDDN %128s", value)==1) {
				strncpy(options.binddn, value, sizeof(options.binddn));
				options.binddn[ sizeof(options.binddn) -1] = '\0';
				if (sscanf(buf, "BINDPW %128s", value)==1)
					strncpy(options.password, value, sizeof(options.password));
					options.password[ sizeof(options.password) -1 ] = '\0';
			}
		}
		fclose(ldap_conf);
	}
	strcpy(options.binddn, "");
	len = strlen(main_argv[0]);
	if (strcmp(main_argv[0]+len-9, "ldap2dnsd")==0) {
		options.is_daemon = 1;
		options.update_iv = UPDATE_INTERVAL;
	} else {
		options.is_daemon = 0;
		options.update_iv = 0;
	}
	ev = getenv("LDAP2DNS_UPDATE");
	if (ev && sscanf(ev, "%d", &len)==1 && len>0) {
		options.update_iv = len;
	}
	options.output = 0;
	ev = getenv("LDAP2DNS_OUTPUT");
	if (ev) {
		if (strcmp(ev, "data")==0)
			options.output = OUTPUT_DATA;
		else if (strcmp(ev, "db")==0)
			options.output = OUTPUT_DB;
	}
	ev = getenv("LDAP2DNS_BINDDN");
	if (ev) {
		strncpy(options.binddn, ev, sizeof(options.binddn));
		options.binddn[ sizeof(options.binddn)-1] = '\0';
		ev = getenv("LDAP2DNS_PASSWORD");
		if (ev){
			strncpy(options.password, ev, sizeof(options.password));
			options.password[ sizeof(options.password) -1 ] = '\0';
		}
	}
	options.verbose = 0;
	options.ldifname[0] = '\0';
	strcpy(options.password, "");
	strcpy(options.exec_command, "");
	while ( (len = getopt(main_argc, main_argv, "b:D:e:h:H:o:p:u:Vv::w:L::"))>0 ) {
		if (optarg && strlen(optarg)>127) {
			fprintf(stderr, "argument %s too long\n", optarg);
			continue;
		}
		switch (len) {
		    case 'b':
			strncpy(options.searchbase, optarg, sizeof(options.searchbase));
			options.searchbase[ sizeof(options.searchbase) -1] = '\0';
			break;
		    case 'u':
			if (sscanf(optarg, "%d", &options.update_iv)!=1)
				options.update_iv = UPDATE_INTERVAL;
			if (options.update_iv<=0) options.update_iv = 1;
			break;
		    case 'D':
			strncpy(options.binddn, optarg, sizeof(options.binddn));
			options.binddn[ sizeof(options.binddn) -1 ] = '\0';
			break;
		    case 'h':
			strncpy(options.hostname[0], optarg, sizeof(options.hostname[0]));
			options.hostname[0][ sizeof(options.hostname[0]) -1 ] = '\0';
			options.usedhosts = 1;
			break;
		case 'H':
			strncpy(options.urildap[0], optarg, sizeof(options.urildap[0]));
			options.urildap[0][ sizeof( options.urildap[0] ) -1 ] = '\0';
			options.useduris = 1;
			break;
		    case 'L':
			if (optarg==NULL)
				strcpy(options.ldifname, "-");
			else{
				strncpy(options.ldifname, optarg, sizeof(options.ldifname));
				options.ldifname[ sizeof( options.ldifname ) -1 ] = '\0';
			}
			break;
		    case 'o':
			options.output = 0;
			if (strcmp(optarg, "data")==0)
				options.output = OUTPUT_DATA;
			else if (strcmp(optarg, "db")==0)
				options.output = OUTPUT_DB;
			break;
		    case 'p':
			if (sscanf(optarg, "%hd", &options.port[0])!=1)
				options.port[0] = LDAP_PORT;
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
			strncpy(options.password, optarg, sizeof(options.password));
			options.password[ sizeof( options.password ) -1 ] = '\0';
			memset(optarg, 'x', strlen(options.password));
			break;
		    case 'e':
			strncpy(options.exec_command, optarg, sizeof(options.exec_command));
			options.exec_command[ sizeof( options.exec_command ) -1 ] = '\0';
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
	char *tmp;
	char *p;
	int i;

	if (strcasecmp(rr->class, "IN"))
		return;
	if (strcasecmp(rr->type, "NS")==0) {
		if (tinyfile) {
			if (znix==0) {
				if (ipdx<=0 && rr->cipaddr[0]) {
					fprintf(tinyfile, "&%s::%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
					if (rr->cname[0])
						fprintf(tinyfile, "=%s:%s:%s:%s:%s\n", rr->cname, rr->cipaddr, rr->ttl, rr->timestamp, rr->location);
					if (ipdx==0)
						fprintf(tinyfile, "+%s:%s:%s:%s:%s\n", rr->cname, rr->ipaddr[0], rr->ttl, rr->timestamp, rr->location);
				} else if (ipdx<0)
					fprintf(tinyfile, "&%s::%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
				else if (ipdx==0)
					fprintf(tinyfile, "&%s:%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->ipaddr[0], rr->cname, rr->ttl, rr->timestamp, rr->location);
				else if (ipdx>0 && rr->cname[0])
					fprintf(tinyfile, "+%s:%s:%s:%s:%s\n", rr->cname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp, rr->location);
			} else if (ipdx<=0) {
				fprintf(tinyfile, "&%s::%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
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
					fprintf(tinyfile, "@%s::%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp, rr->location);
					if (rr->cname[0])
						fprintf(tinyfile, "=%s:%s:%s:%s:%s\n", rr->cname, rr->cipaddr, rr->ttl, rr->timestamp, rr->location);
					if (ipdx==0)
						fprintf(tinyfile, "+%s:%s:%s:%s:%s\n", rr->cname, rr->ipaddr[0], rr->ttl, rr->timestamp, rr->location);
				} else if (ipdx<0)
					fprintf(tinyfile, "@%s::%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp, rr->location);
				else if (ipdx==0)
					fprintf(tinyfile, "@%s:%s:%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->ipaddr[0], rr->cname, rr->preference, rr->ttl, rr->timestamp, rr->location);
				else if (ipdx>0 && rr->cname[0])
					fprintf(tinyfile, "+%s:%s:%s:%s:%s\n", rr->cname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp, rr->location);
			} else if (ipdx<=0) {
				fprintf(tinyfile, "@%s::%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->preference, rr->ttl, rr->timestamp, rr->location);
			}
		}
		if (namedzone) {
			fprintf(namedzone, "%s.\tIN MX\t%s %s.\n", rr->dnsdomainname, rr->preference, rr->cname);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\tIN A\t%s\n", rr->cname, rr->ipaddr[ipdx]);
		}
	} else if ( strcasecmp(rr->type, "A")==0) {
		if (tinyfile) {
			if (ipdx<=0 && rr->cipaddr[0])
				fprintf(tinyfile, "%s%s:%s:%s:%s:%s\n", (znix==0 ? "=" : "+"), rr->dnsdomainname, rr->cipaddr, rr->ttl, rr->timestamp, rr->location);
			if (ipdx>=0)
				fprintf(tinyfile, "+%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->ipaddr[ipdx], rr->ttl, rr->timestamp, rr->location);
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
			snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0]);
		} else {
			strncpy(buf, rr->dnsdomainname, sizeof(buf));
			buf[ sizeof(buf) -1 ] = '\0';
		}
		if (tinyfile)
			fprintf(tinyfile, "^%s:%s:%s:%s:%s\n", buf, rr->cname, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\tIN PTR\t%s.\n", buf, rr->cname);
	} else if (strcasecmp(rr->type, "CNAME")==0) {
		if (tinyfile)
			fprintf(tinyfile, "C%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\tIN CNAME\t%s.\n", rr->dnsdomainname, rr->cname);
	} else if (strcasecmp(rr->type, "TXT")==0) {
		if (tinyfile)
			fprintf(tinyfile, "'%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\tIN TXT\t%s.\n", rr->dnsdomainname, rr->cname);
	} else if (strcasecmp(rr->type, "SRV")==0) {
		if (tinyfile) {
			fprintf(tinyfile, ":%s:33:\\%03o\\%03o\\%03o\\%03o\\%03o\\%03o", rr->dnsdomainname, rr->dnssrvpriority >> 8, rr->dnssrvpriority & 0xff, rr->dnssrvweight >> 8, rr->dnssrvweight & 0xff, rr->dnssrvport >> 8, rr->dnssrvport & 0xff);
			tmp = strdup(rr->cname);
			while (p = strchr(tmp, '.')) {
				*p = '\0';
				p++;
				fprintf(tinyfile, "\\%03o%s", strlen(tmp), tmp);
				tmp = p;
			}
			fprintf(tinyfile, "\\%03o%s", strlen(tmp), tmp);
			fprintf(tinyfile, "\\000:%s:%s:%s\n", rr->ttl, rr->timestamp, rr->location);
		}
		if (namedzone) {
			fprintf(namedzone, "%s\tIN SRV\t%d\t%d\t%d\t%s.\n", rr->dnsdomainname, rr->dnssrvpriority, rr->dnssrvweight, rr->dnssrvport, rr->cname);
		}
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
			snprintf(rr->ipaddr[0], sizeof(rr->ipaddr[0]), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		} else {
			int len = strlen(word1);
			expand_domainname(rr->cname, word1, len);
		}
	} else if (strcasecmp(rr->type, "MX")==0) {
		if (sscanf(word1, "%s", rr->preference)!=1)
			rr->preference[0] = '\0';
		if (sscanf(word2, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
			snprintf(rr->ipaddr[0], sizeof(rr->ipaddr[0]), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		} else {
			int len = strlen(word2);
			expand_domainname(rr->cname, word2, len);
		}
	} else if (strcasecmp(rr->type, "A")==0) {
		if (sscanf(word1, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4)
			snprintf(rr->ipaddr[0], sizeof(rr->ipaddr[0]), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
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

	if ( (ldaperr = ldap_search_s(ldap_con, dn, LDAP_SCOPE_SUBTREE, "objectclass=DNSrrset", NULL, 0, &res))!=LDAP_SUCCESS )
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
		rr.ttl[0] = '\0';
		rr.timestamp[0] = '\0';
		rr.preference[0] = '\0';
		rr.location[0] = '\0';
#if defined DRAFT_RFC
		rr.aliasedobjectname[0] = '\0';
		rr.rr[0] = '\0';
#endif
                rr.dnssrvpriority = 0;
                rr.dnssrvweight = 0;
                rr.dnssrvport = 0;
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
						if (sscanf(bvals[0]->bv_val, "%16s", rr.class)!=1)
							rr.class[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.class);
					} else if (strcasecmp(attr, "DNStype")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", rr.type)!=1)
							rr.type[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.type);
					} else if (strcasecmp(attr, "DNSipaddr")==0) {
						int ip[4];
						for (ipaddresses = 0; bvals[ipaddresses] && ipaddresses<256; ipaddresses++) {
							rr.ipaddr[ipaddresses][0] = '\0';
							if (sscanf(bvals[ipaddresses]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
								snprintf(rr.ipaddr[ipaddresses], sizeof(rr.ipaddr[ipaddresses]), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
								if (options.ldifname[0])
									fprintf(ldifout, "%s: %s\n", attr, rr.ipaddr[ipaddresses]);
							}
						}
					} else if (strcasecmp(attr, "DNScipaddr")==0) {
						int ip[4];
						if (sscanf(bvals[0]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
							snprintf(rr.cipaddr, sizeof(rr.cipaddr), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
							if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, rr.cipaddr);
						}
					} else if (strcasecmp(attr, "DNScname")==0) {
						if (!expand_domainname(rr.cname, bvals[0]->bv_val, bvals[0]->bv_len))
							rr.cname[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSttl")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", rr.ttl)!=1)
							rr.ttl[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.ttl);
					} else if (strcasecmp(attr, "DNStimestamp")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", &rr.timestamp)!=1)
							rr.timestamp[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.timestamp);
					} else if (strcasecmp(attr, "DNSpreference")==0) {
						if (sscanf(bvals[0]->bv_val, "%s", rr.preference)!=1)
							rr.preference[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSlocation")==0) {
						if (sscanf(bvals[0]->bv_val, "%s", rr.location)!=1)
							rr.location[0] = '\0';
						else if (options.ldifname[0])
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
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.aliasedobjectname);
					} else if (strcasecmp(attr, "DNSmacaddress")==0) {
					}
#endif
					else if (strcasecmp(attr, "DNSsrvpriority")==0) {
						if (!(rr.dnssrvpriority = atoi(bvals[0]->bv_val)))
                                                        rr.dnssrvpriority = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.dnssrvpriority);
					} else if (strcasecmp(attr, "DNSsrvweight")==0) {
						if (!(rr.dnssrvweight = atoi(bvals[0]->bv_val)))
                                                        rr.dnssrvweight = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.dnssrvweight);
                                        } else if (strcasecmp(attr, "DNSsrvport")==0) {
						if (!(rr.dnssrvport = atoi(bvals[0]->bv_val)))
                                                        rr.dnssrvport = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.dnssrvport);
                                        }
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
		fprintf(tinyfile, "Z%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s\n",
		    zone.domainname, zone.zonemaster, zone.adminmailbox,
		    zone.serial, zone.refresh, zone.retry, zone.expire,
		    zone.minimum, zone.ttl, zone.timestamp, zone.location);
	}
	if (namedmaster) {
		fprintf(namedmaster, "zone \"%s\" %s {\n\ttype master;\n\tfile \"%s.db\";\n};\n",
		    zone.domainname, zone.class, zone.domainname);
	}
	if (namedzone) {
		fprintf(namedzone, "; Automatically generated by ldap2dns v%s - DO NOT EDIT!\n", VERSION);
		if (zone.ttl[0])
			fprintf(namedzone, "$TTL %s\n", zone.ttl);
		else
			fprintf(namedzone, "$TTL 3600\n");
		fprintf(namedzone, "%s. IN SOA ", zone.domainname);
		len = strlen(zone.zonemaster);
		fprintf(namedzone, (zone.zonemaster[len-1]=='.') ? "%s " : "%s. ", zone.zonemaster);
		len = strlen(zone.adminmailbox);
		fprintf(namedzone, (zone.adminmailbox[len-1]=='.') ? "%s " : "%s. ", zone.adminmailbox);
		fprintf(namedzone, "(\n\t%s\t; Serial\n\t%s\t; Refresh\n\t%s\t; Retry\n\t%s\t; Expire\n\t%s )\t; Minimum\n", zone.serial, zone.refresh, zone.retry, zone.expire, zone.minimum); 
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
		fprintf(tinyfile, "# Automatically generated by ldap2dns v%s - DO NOT EDIT!\n", VERSION);
	if (namedmaster)
		fprintf(namedmaster, "# Automatically generated by ldap2dns v%s - DO NOT EDIT!\n", VERSION);
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
		zone.serial[0] = '\0';
		zone.refresh[0] = '\0';
		zone.retry[0] = '\0';
		zone.expire[0] = '\0';
		zone.minimum[0] = '\0';
		zone.ttl[0] = '\0';
		zone.timestamp[0] = '\0';
		zone.location[0] = '\0';
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
							else if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, zdn[zonenames]);
						}
					} else if (strcasecmp(attr, "DNSserial")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.serial)!=1)
							zone.serial[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.serial);
					} else if (strcasecmp(attr, "DNSrefresh")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.refresh)!=1)
							zone.refresh[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.refresh);
					} else if (strcasecmp(attr, "DNSretry")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.retry)!=1)
							zone.retry[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.retry);
					} else if (strcasecmp(attr, "DNSexpire")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.expire)!=1)
							zone.expire[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.expire);
					} else if (strcasecmp(attr, "DNSminimum")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.minimum)!=1)
							zone.minimum[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.minimum);
					} else if (strcasecmp(attr, "DNSadminmailbox")==0) {
						if (sscanf(bvals[0]->bv_val, "%64s", zone.adminmailbox)!=1)
							zone.adminmailbox[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.adminmailbox);
					} else if (strcasecmp(attr, "DNSzonemaster")==0) {
						if (sscanf(bvals[0]->bv_val, "%64s", zone.zonemaster)!=1)
							zone.zonemaster[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.zonemaster);
					} else if (strcasecmp(attr, "DNSttl")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", zone.ttl)!=1)
							zone.ttl[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.ttl);
					} else if (strcasecmp(attr, "DNStimestamp")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", zone.timestamp)!=1)
							zone.timestamp[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.timestamp);
					} else if (strcasecmp(attr, "DNSlocation")==0) {
						if (sscanf(bvals[0]->bv_val, "%2s", zone.location)!=1)
							zone.location[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, zone.location);
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
				snprintf(namedzonename, sizeof(namedzonename), "%s.db", zone.domainname);
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

static void write_loccode(int lidx)
{
	if (tinyfile) {
		fprintf(tinyfile, "%%%s:%s\n", loc_rec.locname, loc_rec.member[lidx]);
	}
	if (options.ldifname[0])
		fprintf(ldifout, "\n");
}


static void read_loccodes(void)
{
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ldaperr;

	if (tinyfile)
		fprintf(tinyfile, "# Location Codes (if any) - generated by ldap2dns v%s - DO NOT EDIT!\n", VERSION);

	if ( (ldaperr = ldap_search_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, 
								  LDAP_SCOPE_SUBTREE, 
								  "objectclass=DNSloccodes", 
								  NULL, 
								  0, 
								  &res)
			 )!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr;
		char* dn = ldap_get_dn(ldap_con, m);
		int i, locmembers = 0;
		char l_members[256][15];
		//char loc[256][64];
		char loc[2];
		char ldif0;

		loc_rec.locname[0] = '\0';
		if (options.ldifname[0])
			fprintf(ldifout, "dn: %s\n", dn);
		for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
			struct berval** bvals = ldap_get_values_len(ldap_con, m, attr);
			if (bvals!=NULL) {
				if (bvals[0] && bvals[0]->bv_len>0) {
					if (strcasecmp(attr, "objectclass")==0
					    || strcasecmp(attr, "cn")==0) {
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSlocation")==0) {
						if (sscanf(bvals[0]->bv_val, "%2s", loc_rec.locname)!=1)
							loc_rec.locname[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, loc_rec.locname);
					} else if (strcasecmp(attr, "DNSipaddr")==0) {
						for (locmembers = 0; bvals[locmembers] && locmembers<256; locmembers++) {
							if (sscanf(bvals[locmembers]->bv_val, "%15s", loc_rec.member[locmembers])!=1)
								loc_rec.member[locmembers][0] = '\0';
							else if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, loc_rec.member[locmembers]);
						}
					} else {
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					}
				}
				ldap_value_free_len(bvals);
			}
		}
		ldif0 = options.ldifname[0];
		if (options.verbose&1)
			printf("locationcodename: %s (%d members)\n", loc_rec.locname, locmembers);
		for (i = 0; i<locmembers; i++) {
			if (i>0)
				options.ldifname[0] = '\0';
			write_loccode(i);
			if (options.ldifname[0])
				fprintf(ldifout, "\n");
		}
		options.ldifname[0] = ldif0;
		free(dn);
	}
	ldap_msgfree(res);
}


static int do_connect()
{
	int i, version, res;
	struct berval* creds = malloc(sizeof(struct berval));
	struct berval* msgid = malloc(sizeof(struct berval));
	if (options.useduris < 1) {
		fprintf(stderr, "\n[!!] Must define at least one LDAP host with which to connect.\n\n");
		fprintf(stderr, "Use --help to see usage information\n");
		exit(1);
	}

	for (i = 0; i<options.useduris; i++) {
		if ( strlen(options.urildap[i]) > 0) {
			res = ldap_initialize(&ldap_con, options.urildap[i]);
			if (options.verbose&1 && res == LDAP_SUCCESS) {
				printf("ldap_initialization successful (%s)\n", options.urildap[i]);
			} else if ( res != LDAP_SUCCESS ) {
				fprintf(stderr, "ldap_initialization to %s failed %d\n", options.urildap[i], ldap_err2string(res));
				ldap_con = NULL;
				return res;
			}
			version = LDAP_VERSION3;
			if ( (res = ldap_set_option(ldap_con, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_SUCCESS ) {
				fprintf(stderr, "ldap_set_option to %s failed with err %s!\n", options.urildap[i], ldap_err2string(res));
				ldap_con = NULL;
				return res;
			}
			if ( options.use_tls[i] && (res = ldap_start_tls_s( ldap_con, NULL, NULL )) != LDAP_SUCCESS ) {
				fprintf(stderr, "ldap_start_tls_s to %s failed with err %s!\n", options.urildap[i], ldap_err2string(res));
				ldap_con = NULL;
				return res;
			}

			// Yes, you really do use ldap_sasl_bind_s() when doing a simple
			// bind. This is apparently the "new" way, if not entirely obvious
			if (strlen(options.binddn)) {
				if (strlen(options.password)) {
					creds->bv_len = strlen(options.password);
					creds->bv_val = options.password;
				}
				// FIXME: Allow *real* SASL binds
				if ((res = ldap_sasl_bind_s(ldap_con, options.binddn, NULL, creds, NULL, NULL, &msgid)) != LDAP_SUCCESS) {
					fprintf(stderr, "LDAP bind problem:\n\t%s\n", ldap_err2string(res));
					fprintf(stderr, "Attempting to continue with anonymous credentials.\n");
					res = LDAP_SUCCESS;
				}
			}
		}
	}
	return res;
}

void hosts2uri(void)
{
	int i, t;
	// Convert any old host:port sets into URIs.  This allows us
	// to use the more modern ldap_initialize() instead of the
	// deprecated ldap_init()
	for (i = 0; i<options.usedhosts; i++) {
		if ( strlen(options.hostname[i]) > 0) {
			t = options.useduris++;
			snprintf(options.urildap[t],
				sizeof(options.urildap[t]),
				"ldap://%s:%d",
				options.hostname[i],
				options.port[i] ? options.port[i] : LDAP_PORT);
		}
	}
}


int main(int argc, char** argv)
{
	int soa_numzones;
	int soa_checksum;
	int old_numzones;
	int old_checksum;
	int res;

	umask(022);
	main_argc = argc;
	main_argv = argv;
	parse_options();

	if (!options.output) {
		fprintf(stderr, "[!!]\tMust select an output type (\"db\" or \"data\")\n");
		fprintf(stderr, "Use --help to see usage information\n");
		exit(1);
	}

	if (!strlen(options.searchbase)) {
		fprintf(stderr, "[!!]\tMust provide the base DN for the search.\n");
		fprintf(stderr, "Use --help to see usage information\n");
		exit(1);
	}


	/* Initialization complete.  If we're in daemon mode, fork and continue */
	if (options.is_daemon) {
		if (options.is_daemon==1 && fork()) {
			if (options.verbose)
				fprintf(stdout, "Sending process to background.");
			exit(0);
		}

		fprintf(stdout, "ldap2dns v%s starting up", VERSION);
		/* lowest priority */
		nice(19);
	}
	set_datadir();
	for (;;) {
		int ldaperr = -1;

		hosts2uri();
			
		res = do_connect();
		if (res != LDAP_SUCCESS || ldap_con == NULL) {
			fprintf(stderr, "Warning - Problem while connecting to LDAP server:\n\t%s\n", ldap_err2string(res));
			if (options.is_daemon==0)
				break;
			sleep(options.update_iv);
			continue;
		}
		//if (options.is_daemon) {
			calc_checksum(&old_numzones, &old_checksum);
			if (old_numzones!=soa_numzones || old_checksum!=soa_checksum) {
				if (options.verbose&1)
					printf("DNSserial has changed in LDAP zone(s)\n");
				soa_numzones = old_numzones;
				soa_checksum = old_checksum;
			} else {
				goto skip;
			}
		//}
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
		read_loccodes();
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

