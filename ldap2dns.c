/*
 * Create data from an LDAP directory service to be used for tinydns
 * Copyright 2005-2010 by Alkaloid Networks, LLC
 * Copyright 2000-2005 by Jacob Rief <jacob.rief@tiscover.com>
 * License: GPL version 2. See http://www.fsf.org for details
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to:
 * Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA.
 */

#include <lber.h>
#include <ldap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>

#define UPDATE_INTERVAL 59
#define LDAP_CONF "/etc/ldap.conf"
#define OUTPUT_DATA 1
#define OUTPUT_DB 2
#define MAXHOSTS 10
#define DEF_SEARCHTIMEOUT 40
#define DEF_RECLIMIT LDAP_NO_LIMIT
#define MAX_DOMAIN_LEN 256

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
	printf("  Copyright 2005-2010 by Alkaloid Networks, LLC\n");
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
	char dnsdomainname[MAX_DOMAIN_LEN];
	char class[16];
	char type[16];
	char ipaddr[256][80];
	char cipaddr[80];
	char cname[1024]; /* large enough to store DKIM entries, which by rfc5322 have an upper-limit of 998chars */
	char ttl[12];
	char timestamp[20];
	char preference[12];
	char location[2];
#if defined DRAFT_RFC
	char rr[1024];
	char aliasedobjectname[256];
	char macaddress[32];
#endif
	int srvpriority;
	int srvweight;
	int srvport;
	char txt[256];
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
	int foreground;
	unsigned int update_iv;
	unsigned int output;
	int verbose;
	char ldifname[128];
	char exec_command[128];
	int use_tls[MAXHOSTS];
	struct timeval searchtimeout;
	int reclimit;
	int uid;
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
	if (!ev)
		ev = getenv("LDAP2DNS_TINYDNSDIR");
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
	printf("usage: ldap2dns[d] [-df] [-o tinydns|bind] [-h host] [-p port] [-H hostURI] \\\n");
	printf("\t\t[-D binddn] [-w password] [-L[filename]] [-u numsecs] \\\n");
	printf("\t\t[-b searchbase] [-v[v]] [-V] [-t timeout] [-M maxrecords]\n");
	printf("\n");
	printf(" *\tldap2dns formats DNS information from an LDAP server for tinydns or BIND\n");
	printf(" *\tldap2dnsd runs backgrounded refreshing the data on regular intervals\n");
	printf("\n");
	printf("options:\n");
	printf("  -D binddn\tUse the distinguished name binddn to bind to the LDAP directory\n");
	printf("  -w bindpasswd\tUse bindpasswd as the password for simple authentication\n");
	printf("  -b\t\tSearch base to use instead of default\n");
	printf("  -t timeout\tTimeout for LDAP search operations in seconds. Defaults to %d.\n", DEF_SEARCHTIMEOUT);
	printf("  -o tinydns\tGenerate a tinydns compatible \"data\" file\n");
	printf("  -o bind\t\tGenerate a BIND compatible zone files\n");
	printf("  -L [filename]\tPrint output in LDIF format for reimport\n");
	printf("  -h host\tHostname of LDAP server, defaults to localhost\n");
	printf("  -p port\tPort number to connect to LDAP server, defaults to %d\n", LDAP_PORT);
	printf("  -H hostURI\tURI (ldap://hostname or ldaps://hostname of LDAP server\n");
	printf("  -i user\tRun as user\n");
	printf("  -u numsecs\tUpdate DNS data after numsecs. Defaults to %d. Daemon mode only\n\t\t", UPDATE_INTERVAL);
	printf("\n");
	printf("  -e \"exec-cmd\"\tCommand to execute after data is generated\n");
	printf("  -d\t\tRun as a daemon (same as if invoked as ldap2dnsd)\n");
	printf("  -f\t\tIf running as a daemon stay in the foreground (do not fork)\n");
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

static void parse_options()
{
	extern char* optarg;
	char buf[256], value[128];
	int len;
	int c;
	FILE* ldap_conf;
	char* ev;
	int tmp;
	int i;
	long temptime;		// scratch long integer to assign to time_t values
	struct passwd *p;

	/* Initialize the options to their defaults */
	len = strlen(main_argv[0]);
	if (strcmp(main_argv[0]+len-9, "ldap2dnsd")==0) {
		options.is_daemon = 1;
		options.update_iv = UPDATE_INTERVAL;
	} else {
		options.is_daemon = 0;
		options.update_iv = 0;
	}
	strcpy(options.binddn, "");
	strcpy(options.password, "");
	strcpy(options.searchbase, "");
	strcpy(options.hostname[0], "localhost");
	options.port[0] = LDAP_PORT;
	options.searchtimeout.tv_sec = DEF_SEARCHTIMEOUT;
	options.reclimit = DEF_RECLIMIT;
	options.output = 0;
	options.verbose = 0;
	options.ldifname[0] = '\0';
	strcpy(options.exec_command, "");
	options.uid = 0;

	/* Attempt to parse the ldap.conf for system-wide valuse */
	if ((ldap_conf = fopen(LDAP_CONF, "r")) != NULL) {
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
			if (sscanf(buf, "PORT %d", &len)==1)
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

	/* Check the environment for process-local configuration overrides */
        if (getenv("LDAP2DNS_DAEMONIZE") != NULL) {
		options.is_daemon = 1;
		ev = getenv("LDAP2DNS_UPDATE");
		if (ev && sscanf(ev, "%d", &len)==1 && len>0) {
			options.update_iv = len;
		} else {
			/* We have not yet had a chance to override the default
		 	 * interval so use the default.
                 	 */
			options.update_iv = UPDATE_INTERVAL;
		}
	}
	ev = getenv("LDAP2DNS_BINDDN");
	if (ev) {
		strncpy(options.binddn, ev, sizeof(options.binddn));
		options.binddn[ sizeof(options.binddn) -1 ] = '\0';
		ev = getenv("LDAP2DNS_PASSWORD");
		if (ev){
			strncpy(options.password, ev, sizeof(options.password));
			options.password[ sizeof(options.password) -1 ] = '\0';
			memset(ev, 'x', strlen(options.password));
		}
	}
	ev = getenv("LDAP2DNS_BASEDN");
	if (ev) {
		strncpy(options.searchbase, ev, sizeof(options.searchbase));
		options.searchbase[ sizeof(options.searchbase) -1 ] = '\0';
	}
	ev = getenv("LDAP2DNS_HOST");
	if (ev) {
		strncpy(options.hostname[options.usedhosts], ev, sizeof(options.hostname[options.usedhosts]));
		options.hostname[options.usedhosts][ sizeof(options.hostname[options.usedhosts]) -1 ] = '\0';
		options.usedhosts++;
		ev = getenv("LDAP2DNS_PORT");
		if (ev && sscanf(ev, "%d", &tmp) != 1)
			for (i = 0; i<MAXHOSTS; i++)
				options.port[i] = tmp;
	}
	ev = getenv("LDAP2DNS_URI");
	if (ev) {
		if (sscanf(ev, "%512[A-Za-z0-9 .:/_+-]", value)==1)
                                parse_hosts(value);
	}
	if ((ev = getenv("LDAP2DNS_TIMEOUT")) != NULL
	       && sscanf(ev, "%ld", &temptime) == 1)
		options.searchtimeout.tv_sec = temptime;
	if ((ev = getenv("LDAP2DNS_RECLIMIT")) != NULL
	       && sscanf(ev, "%d", &i) == 1)
		options.reclimit = i;
	ev = getenv("LDAP2DNS_OUTPUT");
	if (ev) {
		if (strcmp(ev, "bind")==0)
			options.output = OUTPUT_DB;
		else if (strcmp(ev, "tinydns")==0)
			options.output = OUTPUT_DATA;
		else if (strcmp(ev, "db")==0)
			// Backward compatibility
			options.output = OUTPUT_DB;
		else if (strcmp(ev, "data")==0)
			// Backward compatibility
			options.output = OUTPUT_DATA;
	}
	ev = getenv("LDAP2DNS_VERBOSE");
	if (ev && sscanf(ev, "%d", &options.verbose) != 1)
		options.verbose = 0;
	ev = getenv("LDAP2DNS_EXEC");
	if (ev) {
		strncpy(options.exec_command, ev, sizeof(options.exec_command));
		options.exec_command[ sizeof( options.exec_command ) -1 ] = '\0';
	}
	
	/* Finally, parse command-line options */
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			// name, has_arg, flag, val
			{"help", 0, 0, '?'},
			{"binddn", 1, 0, 'D'},
			{"bindpw", 1, 0, 'w'},
			{"basedn", 1, 0, 'b'},
			{"id", 1, 0, 'i'},
			{"output", 1, 0, 'o'},
			{"ldif", 1, 0, 'L'},
			{"host", 1, 0, 'h'},
			{"port", 1, 0, 'p'},
			{"uri", 1, 0, 'H'},
			{"update", 1, 0, 'u'},
			{"exec", 1, 0, 'e'},
			{"verbose", 0, 0, 'v'},
			{"version", 0, 0, 'V'},
			{"timeout", 1, 0, 't'},
			{"maxrecords", 1, 0, 'M'},
			{"daemonize", 0, 0, 'd'},
			{"foreground", 0, 0, 'f'},
			{0, 0, 0, 0}
		};

		c = getopt_long(main_argc, main_argv, "b:dD:e:fh:H:i:o:p:u:M:m:t:Vv::w:L::", long_options, &option_index);

		if (c == -1)
			break;

		if (optarg && strlen(optarg)>127) {
			fprintf(stderr, "argument %s too long\n", optarg);
			continue;
		}

		switch (c) {
		case 'b':
			strncpy(options.searchbase, optarg, sizeof(options.searchbase));
			options.searchbase[ sizeof(options.searchbase)-1 ] = '\0';
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
			strncpy(options.hostname[options.usedhosts], optarg, sizeof(options.hostname[options.usedhosts]));
			options.hostname[options.usedhosts][ sizeof(options.hostname[options.usedhosts]) -1 ] = '\0';
			options.usedhosts++;
			break;
		case 'H':
			strncpy(options.urildap[0], optarg, sizeof(options.urildap[0]));
			options.urildap[0][ sizeof( options.urildap[0] ) -1 ] = '\0';
			options.useduris = 1;
			break;
		case 'i':
			if ((p = getpwnam(optarg)) != (struct passwd *)0)
				options.uid = p->pw_uid;
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
			if (strcmp(optarg, "tinydns")==0)
				options.output = OUTPUT_DATA;
			else if (strcmp(optarg, "bind")==0)
				options.output = OUTPUT_DB;
			else if (strcmp(optarg, "data")==0)
				// Backward compatibility
				options.output = OUTPUT_DATA;
			else if (strcmp(optarg, "db")==0)
				// Backward compatibility
				options.output = OUTPUT_DB;
			break;
		case 'p':
			if (sscanf(optarg, "%hd", &options.port[0])!=1)
				options.port[0] = LDAP_PORT;
			break;
		case 'v':
			if (optarg)
				options.verbose = strlen(optarg) + 1;
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
		case 't':
			if (sscanf(optarg, "%ld", &temptime)!=1)
				options.searchtimeout.tv_sec = DEF_SEARCHTIMEOUT;
			else
				options.searchtimeout.tv_sec = temptime;
			break;
		case 'M':
			if (sscanf(optarg, "%d", &options.reclimit)!=1)
				options.reclimit = DEF_RECLIMIT;
			break;
		case 'd':
			options.is_daemon = 1;
			break;
		case 'f':
			options.foreground = 1;
			break;
		case '?':
		default:
			print_usage();
			exit(1);
		}
	}
	if (options.is_daemon==1 && options.foreground==1) {
		options.is_daemon = 2; /* foreground daemon */
		if (options.update_iv == 0)	/* make sure we've got a nonzero update interval in foreground-daemon mode */
			options.update_iv = UPDATE_INTERVAL;
	}
}


static int expand_domainname(char target[MAX_DOMAIN_LEN], const char* source, int slen)
{
	int tlen;
	tlen = strlen(zone.domainname);

	if ((slen + tlen) > MAX_DOMAIN_LEN)
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


#if defined DRAFT_RFC
static int expand_reverse(char target[64], const char* source)
{
}
#endif


static void write_rr(struct resourcerecord* rr, int ipdx, int znix)
{
	char *tmp;
	char *p;
	int i;
	int res;
	unsigned char in6addr[sizeof(struct in6_addr)];

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
			fprintf(namedzone, "%s.\t%s\tIN NS\t%s.\n", rr->dnsdomainname, rr->ttl, rr->cname);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\t%s\tIN A\t%s\n", rr->cname, rr->ttl, rr->ipaddr[ipdx]);
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
			fprintf(namedzone, "%s.\t%s\tIN MX\t%s %s.\n", rr->dnsdomainname, rr->ttl, rr->preference, rr->cname);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\t%s\tIN A\t%s\n", rr->cname, rr->ttl, rr->ipaddr[ipdx]);
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
				fprintf(namedzone, "%s.\t%s\tIN A\t%s\n", rr->dnsdomainname, rr->ttl, rr->cipaddr);
			if (ipdx>=0)
				fprintf(namedzone, "%s.\t%s\tIN A\t%s\n", rr->dnsdomainname, rr->ttl, rr->ipaddr[ipdx]);
		}
	} else if (strcasecmp(rr->type, "PTR")==0) {
		int ip[4] = {0, 0, 0, 0};
		char buf[256];
		char tmp[8];
		if (ipdx>0) {
			/* does not make to have more than one IPaddr for a PTR record */
			return;
		}
		if (ipdx==0 && sscanf(rr->ipaddr[0], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
			/* lazy user, used DNSipaddr for reverse lookup */
			snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0]);
		} else if (ipdx==0 && inet_pton(AF_INET6, rr->ipaddr[0], in6addr)==1) {
			*buf = '\0';
			for (i = 15; i >= 0; i--) {
				sprintf(tmp, "%x.", in6addr[i] & 0xf);
				strcat(buf, tmp);
				sprintf(tmp, "%x.", in6addr[i] >> 4);
				strcat(buf, tmp);
			}
			strcat(buf, "ip6.int.");
		} else {
			strncpy(buf, rr->dnsdomainname, sizeof(buf));
			buf[ sizeof(buf) -1 ] = '\0';
		}
		if (tinyfile)
			fprintf(tinyfile, "^%s:%s:%s:%s:%s\n", buf, rr->cname, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\t%s\tIN PTR\t%s.\n", buf, rr->ttl, rr->cname);
	} else if (strcasecmp(rr->type, "CNAME")==0) {
		if (tinyfile)
			fprintf(tinyfile, "C%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->cname, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\t%s\tIN CNAME\t%s.\n", rr->dnsdomainname, rr->ttl, rr->cname);
	} else if (strcasecmp(rr->type, "TXT")==0) {
		if (tinyfile)
			fprintf(tinyfile, "'%s:%s:%s:%s:%s\n", rr->dnsdomainname, rr->txt, rr->ttl, rr->timestamp, rr->location);
		if (namedzone)
			fprintf(namedzone, "%s.\t%s\tIN TXT\t\"%s\"\n", rr->dnsdomainname, rr->ttl, rr->txt);
	} else if (strcasecmp(rr->type, "SRV")==0) {
		if (tinyfile) {
			fprintf(tinyfile, ":%s:33:\\%03o\\%03o\\%03o\\%03o\\%03o\\%03o", rr->dnsdomainname, rr->srvpriority >> 8, rr->srvpriority & 0xff, rr->srvweight >> 8, rr->srvweight & 0xff, rr->srvport >> 8, rr->srvport & 0xff);
			tmp = strdup(rr->cname);
			while ((p = strchr(tmp, '.')) != NULL) {
				*p = '\0';
				p++;
				fprintf(tinyfile, "\\%03o%s", (unsigned)strlen(tmp), tmp);
				tmp = p;
			}
			fprintf(tinyfile, "\\%03o%s", (unsigned)strlen(tmp), tmp);
			fprintf(tinyfile, "\\000:%s:%s:%s\n", rr->ttl, rr->timestamp, rr->location);
		}
		if (namedzone) {
			fprintf(namedzone, "%s.\t%s\tIN SRV\t%d\t%d\t%d\t%s.\n", rr->dnsdomainname, rr->ttl, rr->srvpriority, rr->srvweight, rr->srvport, rr->cname);
		}
	} else if (strcasecmp(rr->type, "AAAA")==0) {
		/* Even though we don't use the result of inet_pton() for BIND,
		 * we can use it to validate the address. */
		if (strlen(rr->cipaddr) > 0) {
			res = inet_pton(AF_INET6, rr->cipaddr, in6addr);
		} else {
			res = inet_pton(AF_INET6, rr->ipaddr[0], in6addr);
		}
		if (res == 1) {
			/* Valid IPv6 address found. */
			if (tinyfile) {
				fprintf(tinyfile, ":%s:28:", rr->dnsdomainname);
				for (i=0;i<16;i++) {
					fprintf(tinyfile, "\\%03o", in6addr[i]);
				}
				fprintf(tinyfile, ":%s:%s:%s\n", rr->ttl, rr->timestamp, rr->location);
			}
			if (namedzone) {
				fprintf(namedzone, "%s.\t%s\tIN AAAA\t%s\n", rr->dnsdomainname, rr->ttl, rr->ipaddr[0]);
			}
		} else {
			fprintf(stderr, "[**] Invalid IPv6 address found for %s; skipping record.\n", rr->dnsdomainname);
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
		strncpy(rr->cname, word1, sizeof(rr->cname));
	}
}
#endif


static void read_resourcerecords(char* dn, int znix)
{
	LDAPMessage* res = NULL;
	LDAPMessage* m;
	int ldaperr;

	if ( (ldaperr = ldap_search_ext_s(ldap_con, dn, LDAP_SCOPE_SUBTREE, "objectclass=DNSrrset", NULL, 0, NULL, NULL, &options.searchtimeout, options.reclimit, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	if (ldap_count_entries(ldap_con, res) < 1) {
		fprintf(stderr, "\n[**] Warning: No DNS records found for domain %s.\n\n", zone.domainname);
		return;
	}
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
                rr.srvpriority = 0;
                rr.srvweight = 0;
                rr.srvport = 0;
		for (attr = ldap_first_attribute(ldap_con, m, &ber); attr; attr = ldap_next_attribute(ldap_con, m, ber)) {
			struct berval** bvals;

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
						unsigned char in6addr[sizeof(struct in6_addr)];
						for (ipaddresses = 0; bvals[ipaddresses] && ipaddresses<256; ipaddresses++) {
							rr.ipaddr[ipaddresses][0] = '\0';
							if (inet_pton(AF_INET6, bvals[ipaddresses]->bv_val, in6addr)==1) {
								snprintf(rr.ipaddr[ipaddresses], sizeof(rr.ipaddr[ipaddresses]), "%s", bvals[ipaddresses]->bv_val);
								if (options.ldifname[0])
									fprintf(ldifout, "%s: %s\n", attr, rr.ipaddr[ipaddresses]);
							} else if (sscanf(bvals[ipaddresses]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
								snprintf(rr.ipaddr[ipaddresses], sizeof(rr.ipaddr[ipaddresses]), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
								if (options.ldifname[0])
									fprintf(ldifout, "%s: %s\n", attr, rr.ipaddr[ipaddresses]);
							}
						}
					} else if (strcasecmp(attr, "DNScipaddr")==0) {
						int ip[4];
						unsigned char in6addr[sizeof(struct in6_addr)];
						if (inet_pton(AF_INET6, bvals[0]->bv_val, in6addr)==1) {
							snprintf(rr.cipaddr, sizeof(rr.cipaddr), "%s", bvals[0]->bv_val);
							if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, rr.cipaddr);
						} else if (sscanf(bvals[0]->bv_val, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])==4) {
							snprintf(rr.cipaddr, sizeof(rr.cipaddr), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
							if (options.ldifname[0])
								fprintf(ldifout, "%s: %s\n", attr, rr.cipaddr);
						}
					} else if (strcasecmp(attr, "DNScname")==0) {
						if (!expand_domainname(rr.cname, bvals[0]->bv_val, bvals[0]->bv_len))
							rr.cname[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNStxt")==0) {
						strncpy(rr.txt, bvals[0]->bv_val, sizeof(rr.txt) - 1);
						if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, bvals[0]->bv_val);
					} else if (strcasecmp(attr, "DNSttl")==0) {
						if (sscanf(bvals[0]->bv_val, "%12s", rr.ttl)!=1)
							rr.ttl[0] = '\0';
						else if (options.ldifname[0])
							fprintf(ldifout, "%s: %s\n", attr, rr.ttl);
					} else if (strcasecmp(attr, "DNStimestamp")==0) {
						if (sscanf(bvals[0]->bv_val, "%16s", rr.timestamp)!=1)
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
						if (!(rr.srvpriority = atoi(bvals[0]->bv_val)))
                                                        rr.srvpriority = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.srvpriority);
					} else if (strcasecmp(attr, "DNSsrvweight")==0) {
						if (!(rr.srvweight = atoi(bvals[0]->bv_val)))
                                                        rr.srvweight = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.srvweight);
                                        } else if (strcasecmp(attr, "DNSsrvport")==0) {
						if (!(rr.srvport = atoi(bvals[0]->bv_val)))
                                                        rr.srvport = 0;
                                                else if (options.ldifname[0])
                                                        fprintf(ldifout, "%s: %d\n", attr, rr.srvport);
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
		fprintf(namedzone, ";\n; Automatically generated by ldap2dns v%s - DO NOT EDIT!\n;\n\n", VERSION);
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
	if ( (ldaperr = ldap_search_ext_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSzone", attr_list, 0, NULL, NULL, &options.searchtimeout, options.reclimit, &res)) != LDAP_SUCCESS )
		die_ldap(ldaperr);
	if (ldap_count_entries(ldap_con, res) < 1) {
		fprintf(stderr, "\n[**] Warning: No records returned from search.  Check for correct credentials,\n[**] LDAP hostname, and search base DN.\n\n");
		return;
	}
		
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
		fprintf(tinyfile, "#\n# Automatically generated by ldap2dns v%s - DO NOT EDIT!\n#\n\n", VERSION);
	if (namedmaster)
		fprintf(namedmaster, "#\n# Automatically generated by ldap2dns v%s - DO NOT EDIT!\n#\n\n", VERSION);
	if ( (ldaperr = ldap_search_ext_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSzone", NULL, 0, NULL, NULL, &options.searchtimeout, options.reclimit, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);
	if (ldap_count_entries(ldap_con, res) < 1) {
		fprintf(stderr, "\n[**] Warning: No records returned from search.  Check for correct credentials,\n[**] LDAP hostname, and search base DN.\n\n");
		return;
	}
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
							if (sscanf(bvals[zonenames]->bv_val, "%64s", zdn[zonenames])!=1)
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
				char namedzonename[128], *s;
				int i;
				snprintf(namedzonename, sizeof(namedzonename), "%s.db", zone.domainname);
				for (s = namedzonename ; (i = *s) != '\0' ; ++s)
					if (i == '/')
						*s = '_';
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

	if ( (ldaperr = ldap_search_ext_s(ldap_con, options.searchbase[0] ? options.searchbase : NULL, LDAP_SCOPE_SUBTREE, "objectclass=DNSloccodes", NULL, 0, NULL, NULL, &options.searchtimeout, options.reclimit, &res))!=LDAP_SUCCESS )
		die_ldap(ldaperr);

	// We aren't going to warn for zero records here as many installs do
	// not use location codes at all
	if ((ldap_count_entries(ldap_con, res) > 0) && tinyfile) {
		fprintf(tinyfile, "#\n# Location Codes (if any) - generated by ldap2dns v%s - DO NOT EDIT!\n#\n\n", VERSION);
	} else {
		return;
	}

	for (m = ldap_first_entry(ldap_con, res); m; m = ldap_next_entry(ldap_con, m)) {
		BerElement* ber = NULL;
		char* attr;
		char* dn = ldap_get_dn(ldap_con, m);
		int i, locmembers = 0;
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
				fprintf(stderr, "ldap_initialization to %s failed %s\n", options.urildap[i], ldap_err2string(res));
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
	int old_numzones = 0;
	int old_checksum = 0;
	int res;

	umask(022);
	main_argc = argc;
	main_argv = argv;
	parse_options();

	if (!options.output) {
		fprintf(stderr, "[!!]\tMust select an output type (\"bind\" or \"tinydns\")\n");
		fprintf(stderr, "Use --help to see usage information\n");
		exit(1);
	}

	if (!strlen(options.searchbase)) {
		fprintf(stderr, "[!!]\tMust provide the base DN for the search.\n");
		fprintf(stderr, "Use --help to see usage information\n");
		exit(1);
	}

	if (options.uid && setuid(options.uid) == -1)
		die_exit("Unable to set userid");

	/* Initialization complete.  If we're in daemon mode, fork and continue */
	if (options.is_daemon) {
		fprintf(stdout, "ldap2dns v%s starting up\n", VERSION);
		if (options.is_daemon==1 && fork()) {
			if (options.verbose)
				fprintf(stdout, "Sending process to background.");
			exit(0);
		}

		/* lowest priority */
		if (nice(19) == -1)
			fprintf(stderr, "ldap2dns: warning, unable to nice(19)\n");
	}
	set_datadir();

	/* Convert our list of hosts into ldap_initialize() compatible URIs */
	hosts2uri();

	/* Main loop */
	for (;;) {
		int ldaperr = -1;

			
		res = do_connect();
		if (res != LDAP_SUCCESS || ldap_con == NULL) {
			fprintf(stderr, "Warning - Problem while connecting to LDAP server:\n\t%s\n", ldap_err2string(res));
			if (options.is_daemon==0)
				break;
			sleep(options.update_iv);
			continue;
		}
		calc_checksum(&soa_numzones, &soa_checksum);
		if (old_numzones!=soa_numzones || old_checksum!=soa_checksum) {
			if (options.verbose&1)
				printf("DNSserial has changed in LDAP zone(s)\n");
			old_numzones = soa_numzones;
			old_checksum = soa_checksum;
		} else {
			goto skip;
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
		if (options.exec_command[0] && system(options.exec_command) == -1)
			fprintf(stderr, "ldap2dns: warning, unable to system(\"%s\")\n", options.exec_command);
	    skip:
		if ( (ldaperr = ldap_unbind_ext_s(ldap_con, NULL, NULL))!=LDAP_SUCCESS )
			die_ldap(ldaperr);
		if (options.is_daemon==0)
			break;
		sleep(options.update_iv);
	}
	return 0;
}
