/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
%{
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <pcap.h>
#include <dnet.h>

#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "router.h"
#include "plugins_config.h"
#include "plugins.h"
#include "template.h"
#include "condition.h"
#include "interface.h"
#include "ethernet.h"
#include "pfvar.h"
#include "dhcpclient.h"
#include "subsystem.h"
#include "util.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

int hydlex(void);
int hydparse(void);
int hyderror(char *, ...);
int hydwarn(char *, ...);
int hydprintf(char *, ...);
void *hyd_scan_string(char *);
int hyd_delete_buffer(void *);

#define yylex hydlex
#define yyparse hydparse
#define yy_scan_string hyd_scan_string
#define yy_delete_buffer hyd_delete_buffer
#define yyerror hyderror
#define yywarn hydwarn
#define yyprintf hydprintf
#define yyin hydin

extern int honeyd_verify_config;

pf_osfp_t pfctl_get_fingerprint(const char *);
struct action *honeyd_protocol(struct template *, int);
void port_action_clone(struct action *, struct action *);
static void dhcp_template(struct template *tmpl,
    char *interface, char *mac_addr);

static struct evbuffer *buffer = NULL;
int lineno;
char *filename;
int errors = 0;
int curtype = -1;	/* Lex sets it to SOCK_STREAM or _DGRAM */

%}

%token	CREATE ADD PORT BIND CLONE DOT FILTERED OPEN CLOSED DEFAULT SET ACTION
%token	PERSONALITY RANDOM ANNOTATE NO FINSCAN FRAGMENT DROP OLD NEW COLON
%token	PROXY UPTIME DROPRATE IN SYN UID GID ROUTE ENTRY LINK NET UNREACH
%token	SLASH LATENCY MS LOSS BANDWIDTH SUBSYSTEM OPTION TO SHARED NETWORK
%token	SPOOF FROM TEMPLATE BROADCAST
%token  TUNNEL TARPIT DYNAMIC USE IF OTHERWISE EQUAL SOURCE OS IP BETWEEN
%token  DELETE LIST ETHERNET DHCP ON MAXFDS RESTART DEBUG
%token	DASH TIME INTERNAL
%token	<string> STRING
%token	<string> CMDSTRING
%token	<string> IPSTRING
%token	<number> NUMBER
%token	<number> PROTO
%token	<floatp> FLOAT
%type	<addr> ipaddr
%type	<addr> ipnet
%type	<ai> ipaddrplusport
%type	<action> action
%type	<tmpl> template
%type	<pers> personality
%type	<number> finscan;
%type	<fragp> fragment;
%type	<floatp> rate;
%type	<drop> randomearlydrop;
%type	<number> latency;
%type	<number> bandwidth;
%type	<number> packetloss;
%type	<number> shared;
%type	<number> restart;
%type	<number> flags;
%type   <condition> condition;
%type	<timecondition> timecondition;
%type	<time> time;
%union {
	char *string;
	int number;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality *pers;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;
}
%%

config		: /* empty */
		| config creation
		| config addition
		| config delete
		| config subsystem
		| config binding
		| config set
		| config annotate
		| config route
		| config option
		| config ui
		;

creation	: CREATE STRING
	{
		if (template_create($2) == NULL)
			yyerror("Template \"%s\" exists already", $2);
		free($2);
	}
		| CREATE TEMPLATE
	{
		if (template_create("template") == NULL)
			yyerror("Template \"template\" exists already");
	}
		| CREATE DEFAULT
	{
		if (template_create("default") == NULL)
			yyerror("Template \"default\" exists already");
	}
		| DYNAMIC STRING
	{		
		struct template *tmpl;
		if ((tmpl = template_create($2)) == NULL)
			yyerror("Template \"%s\" exists already", $2);
		tmpl->flags |= TEMPLATE_DYNAMIC;
		free($2);
	}
;

delete		: DELETE template
	{
		if ($2 != NULL)
			template_free($2);
	}
		| DELETE template PROTO PORT NUMBER
	{
		struct port *port;
		if ((port = port_find($2, $3, $5)) == NULL) {
			yyerror("Cannot find port %d in \"%s\"",
			    $5, $2->name);
		} else {
			port_free($2, port);
		}
	}
;
addition	: ADD template PROTO PORT NUMBER action
	{
		struct action *action;		
		if ($2 == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol($2, $3)) == NULL) {
			yyerror("Bad protocol");
			break;
		}
		if ($2 != NULL && template_add($2, $3, $5, &$6) == -1)
			yyerror("Cannot add port %d to template \"%s\"",
			    $5, $2 != NULL ? $2->name : "<unknown>");
		if ($6.action)
			free($6.action);
	}
		| ADD template USE template IF condition
	{	
		if ($2 == NULL || $4 == NULL)
			break;
		if (!($2->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", $2->name);
		template_insert_dynamic($2, $4, &$6);
	}
		| ADD template OTHERWISE USE template
	{	
		if ($2 == NULL || $5 == NULL)
			break;
		if (!($2->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", $2->name);
		template_insert_dynamic($2, $5, NULL);
	}
;
subsystem	: ADD template SUBSYSTEM CMDSTRING shared restart
	{
		int flags = 0;

		if ($5)
			flags |= SUBSYSTEM_SHARED;		
		if ($6)
			flags |= SUBSYSTEM_RESTART;		

		$4[strlen($4) - 1] = '\0';
		if ($2 != NULL &&
		    template_subsystem($2, $4+1, flags) == -1)
			yyerror("Can not add subsystem \"%s\" to template \"%s\"",
			    $4+1, $2 != NULL ? $2->name : "<unknown>");
		free($4);
	}
;
binding		: BIND ipaddr template
	{
		/* Bind to an IP address and start subsystems */
		if ($3 == NULL) {
			yyerror("Unknown template");
			break;
		}

		if ($3->ethernet_addr != NULL) {
			struct interface *inter;
			inter = interface_find_responsible(&$2);
			if (inter == NULL ||
			    inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
				yyerror("Template \"%s\" is configured with "
				    "ethernet address but there is no "
				    "interface that can reach %s",
				    $3->name, addr_ntoa(&$2));
				break;
			} else {
				$3->addrbits = inter->if_addrbits;
			}
		}

		if (template_clone(addr_ntoa(&$2), $3, NULL, 1) == NULL) {
			yyerror("Binding to %s failed", addr_ntoa(&$2));
			break;
		}
	}
		| BIND condition ipaddr template
	{
		struct template *tmpl;

		/* Special magic */
		if ((tmpl = template_find(addr_ntoa(&$3))) != NULL) {
			if (!(tmpl->flags & TEMPLATE_DYNAMIC)) {
				yyerror("Template \"%s\" already specified as "
				    "non-dynamic template", addr_ntoa(&$3));
				break;
			}
		} else if ((tmpl = template_create(addr_ntoa(&$3))) == NULL) {
			yyerror("Could not create template \"%s\"",
			    addr_ntoa(&$3));
			break;
		}
		tmpl->flags |= TEMPLATE_DYNAMIC;

		/* 
		 * Add this point we do have the right template.
		 * We just need to add the proper condition.
		 */
		template_insert_dynamic(tmpl, $4, &$2);
	}
		| BIND ipaddr TO STRING
	{
		struct interface *inter;
		struct template *tmpl;

		/* Bind an IP address to an external interface */
		if ((inter = interface_find($4)) == NULL) {
			yyerror("Interface \"%s\" does not exist.", $4);
			free($4);
			break;
		}
		if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
			yyerror("Interface \"%s\" does not support ARP.", $4);
			free($4);
			break;
		}

		if ((tmpl = template_create(addr_ntoa(&$2))) == NULL) {
			yyerror("Template \"%s\" exists already",
			    addr_ntoa(&$2));
			break;
		}

		/* Make this template external. */
		tmpl->flags |= TEMPLATE_EXTERNAL;
		tmpl->inter = inter;
		free($4);
	}
		| DHCP template ON STRING
	{		
		/* Automagically assign DHCP address */
		dhcp_template($2, $4, NULL);
		free($4);
	}		
		| DHCP template ON STRING ETHERNET CMDSTRING
	{		
		/* Automagically assign DHCP address with MAC address */
		$6[strlen($6) - 1] = '\0';
		dhcp_template($2, $4, $6 + 1);
		free($4);
		free($6);
	}		
		| CLONE STRING template
	{
		/* Just clone.  This is not the final destination yet */
		if ($3 == NULL || template_clone($2, $3, NULL, 0) == NULL)
			yyerror("Cloning to %s failed", $2);
		free($2);
	}
		| SET template SPOOF FROM ipaddr
	{
		if ($2 == NULL) {
			yyerror("No template");
			break;
		}
		$2->spoof.new_src = $5;
	}
		| SET template SPOOF TO ipaddr
	{
		if ($2 == NULL) {
			yyerror("No template");
			break;
		}
		$2->spoof.new_dst = $5;
	}
		| SET template SPOOF FROM ipaddr TO ipaddr
	{
		if ($2 == NULL) {
			yyerror("No template");
			break;
		}
		$2->spoof.new_src = $5;
		$2->spoof.new_dst = $7;
	}
;
set		: SET template DEFAULT PROTO ACTION action
	{
		struct action *action;

		if ($2 == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol($2, $4)) == NULL) {
			yyerror("Bad protocol");
			break;
		}

		port_action_clone(action, &$6);
		if ($6.action != NULL)
			free($6.action);
	}
		| SET template PERSONALITY personality
	{
		if ($2 == NULL || $4 == NULL)
			break;
		$2->person = personality_clone($4);
	}
		| SET template ETHERNET CMDSTRING
	{
		extern int need_arp;
		if ($2 == NULL || $4 == NULL)
			break;
		$4[strlen($4) - 1] = '\0';
		$2->ethernet_addr = ethernetcode_make_address($4 + 1);
		if ($2->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", $4 + 1);
		}
		/*** small patch to make sure the ethernet adress is used ***/
		/*** even if none were set in the default template ***/
		struct addr addr;
		struct in_addr inp;
		if(inet_aton($2->name, &inp) == 0)
		{
			addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &inp.s_addr, IP_ADDR_LEN);
			template_post_arp($2, &addr);
		}
		/*** end patch ***/
		free ($4);

		need_arp = 1;
	}
		| SET template UPTIME NUMBER
	{
		if ($2 == NULL || $4 == 0)
			break;
		$2->timestamp = $4 * 2;
	}
		| SET template DROPRATE IN rate
	{
		if ($2 == NULL)
			break;
		if ($5 > 100) {
			yyerror("Droprate too high: %f", $5);
			break;
		}

		$2->drop_inrate = $5 * 100;
	}
		| SET template DROPRATE SYN rate
	{
		if ($2 == NULL)
			break;
		if ($5 > 100) {
			yyerror("Droprate too high: %f", $5);
			break;
		}

		$2->drop_synrate = $5 * 100;
	}
		| SET template MAXFDS NUMBER
	{
		if ($2 == NULL)
			break;
		if ($4 <= 3) {
			yyerror("Bad number of max file descriptors %d", $4);
			break;
		}
		$2->max_nofiles = $4;
	}
		| SET template UID NUMBER
	{
		if ($2 == NULL)
			break;
		if (!$4) {
			yyerror("Bad uid %d", $4);
			break;
		}
		$2->uid = $4;
		honeyd_use_uid($4);
	}
		| SET template UID NUMBER GID NUMBER
	{
		if ($2 == NULL)
			break;
		if (!$4 || !$6) {
			yyerror("Bad uid %d, gid %d", $4, $6);
			break;
		}
		$2->uid = $4;
		$2->gid = $6;
		honeyd_use_uid($4);
		honeyd_use_gid($6);
	}
;
annotate	: ANNOTATE personality finscan
	{
		if ($2 == NULL)
			break;
		$2->disallow_finscan = !$3;
	}
		| ANNOTATE personality fragment
	{
		if ($2 == NULL)
			break;
		$2->fragp = $3;
	}
;
route		: ROUTE ENTRY ipaddr
	{
		if (router_start(&$3, NULL) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&$3));
	}
		| ROUTE ENTRY ipaddr NETWORK ipnet
	{
		if (router_start(&$3, &$5) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&$3));
	}
		| ROUTE ipaddr ADD NET ipnet ipaddr latency packetloss bandwidth randomearlydrop
	{
		struct router *r, *newr;
		struct addr defroute;

		if ((r = router_find(&$2)) == NULL &&
		    (r = router_new(&$2)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&$2));
			break;
		}
		if ((newr = router_find(&$6)) == NULL)
			newr = router_new(&$6);
		if (router_add_net(r, &$5, newr, $7, $8, $9, &$10) == -1)
			yyerror("Could not add route to %s", addr_ntoa(&$5));

		if ($9 == 0 && $10.high != 0)
			yywarn("Ignoring drop between statement without "
			       "specified bandwidth.");

		addr_pton("0.0.0.0/0", &defroute);
		defroute.addr_bits = 0; /* work around libdnet bug */

		/* Only insert a reverse route, if the current route is
		 * not the default route.
		 */
		if (addr_cmp(&defroute, &$5) != 0 &&
		    router_add_net(newr, &defroute, r, $7, $8, $9, &$10) == -1)
			yyerror("Could not add default route to %s",
			    addr_ntoa(&$5));
	}
		| ROUTE ipaddr ADD NET ipnet TUNNEL ipaddr ipaddr
	{
		struct router *r;

		if ((r = router_find(&$2)) == NULL &&
		    (r = router_new(&$2)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&$2));
			break;
		}
		if (router_add_tunnel(r, &$5, &$7, &$8) == -1)
			yyerror("Could not add tunnel to %s", addr_ntoa(&$8));
	}
		| ROUTE ipaddr LINK ipnet
	{
		struct router *r;

		if ((r = router_find(&$2)) == NULL &&
		    (r = router_new(&$2)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&$2));
			break;
		}
		if (router_add_link(r, &$4) == -1)
			yyerror("Could not add link %s", addr_ntoa(&$4));
	}
		| ROUTE ipaddr UNREACH ipnet
	{
		struct router *r;

		if ((r = router_find(&$2)) == NULL &&
		    (r = router_new(&$2)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&$2));
			break;
		}
		if (router_add_unreach(r, &$4) == -1)
			yyerror("Could not add unreachable net %s",
			    addr_ntoa(&$4));
	}
;
finscan		: FINSCAN	{ $$ = 1; }
		| NO FINSCAN	{ $$ = 0; }
;
fragment	: FRAGMENT DROP	{ $$ = FRAG_DROP; }
		| FRAGMENT OLD	{ $$ = FRAG_OLD; }
		| FRAGMENT NEW	{ $$ = FRAG_NEW; }
;
ipaddr		: IPSTRING
	{
		if (addr_pton($1, &$$) < 0)
			yyerror("Illegal IP address %s", $1);
		free($1);
	}
		| CMDSTRING
	{
		struct addrinfo ai, *aitop;

		memset(&ai, 0, sizeof (ai));
		ai.ai_family = AF_INET;
		ai.ai_socktype = 0;
		ai.ai_flags = 0;

		/* Remove quotation marks */
		$1[strlen($1) - 1] = '\0';
		if (getaddrinfo($1+1, NULL, &ai, &aitop) != 0) {
			yyerror("getaddrinfo failed: %s", $1+1);
			break;
		}
		addr_ston(aitop->ai_addr, &$$);
		freeaddrinfo(aitop);
		free($1);
	}
;
ipnet		: ipaddr SLASH NUMBER
	{
		char src[25];
		struct addr b;
		snprintf(src, sizeof(src), "%s/%d",
		    addr_ntoa(&$1), $3);
		if (addr_pton(src, &$$) < 0)
			yyerror("Illegal IP network %s", src);
		/* Fix libdnet error */
		if ($3 == 0)
			$$.addr_bits = 0;

		/* Test if this is a legal network */
		addr_net(&$$, &b);
		b.addr_bits = $$.addr_bits;
		if (memcmp(&$$.addr_ip, &b.addr_ip, IP_ADDR_LEN)) {
			$$ = b;
			yywarn("Bad network mask in %s", src);
		}
	}
;
ipaddrplusport	: ipaddr COLON NUMBER
	{
		if (curtype == -1) {
			yyerror("Bad port type");
			break;
		}
		$$ = cmd_proxy_getinfo(addr_ntoa(&$1), curtype, $3);
		curtype = -1;
		if ($$ == NULL)
			yyerror("Illegal IP address port pair");
	}
;
action		: flags STRING
	{
		memset(&$$, 0, sizeof($$));
		$$.action = $2;
		$$.flags = $1;
		$$.status = PORT_OPEN;
	}
		| flags CMDSTRING
	{
		memset(&$$, 0, sizeof($$));
		$2[strlen($2) - 1] = '\0';
		if (($$.action = strdup($2 + 1)) == NULL)
			yyerror("Out of memory");
		$$.status = PORT_OPEN;
		$$.flags = $1;
		free($2);
	}
		| flags INTERNAL CMDSTRING
	{
#ifdef HAVE_PYTHON
		memset(&$$, 0, sizeof($$));
		$3[strlen($3) - 1] = '\0';
		if (($$.action_extend = pyextend_load_module($3+1)) == NULL)
			yyerror("Bad python module: \"%s\"", $3+1);
		$$.status = PORT_PYTHON;
		$$.flags = $1;
		free($3);
#else
		yyerror("Python support is not available.");
#endif
	}
		| flags PROXY ipaddrplusport
	{
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_PROXY;
		$$.action = NULL;
		$$.aitop = $3;
		$$.flags = $1;
	}
		| flags PROXY STRING COLON NUMBER
	{
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_PROXY;
		$$.action = NULL;
		$$.aitop = NULL;
		$$.flags = $1;
		if ($3[0] != '$') {
			if (curtype == -1) {
				yyerror("Bad port type");
				break;
			}
			$$.aitop = cmd_proxy_getinfo($3, curtype, $5);
			curtype = -1;
			if ($$.aitop == NULL)
				yyerror("Illegal host name in proxy");
		} else {
			char proxy[1024];

			snprintf(proxy, sizeof(proxy), "%s:%d", $3, $5);
			$$.action = strdup(proxy);
			if ($$.action == NULL)
				yyerror("Out of memory");
		}
		free($3);
	}
		| flags PROXY STRING COLON STRING
	{
		char proxy[1024];
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_PROXY;
		$$.action = NULL;
		$$.aitop = NULL;
		$$.flags = $1;

		snprintf(proxy, sizeof(proxy), "%s:%s", $3, $5);
		$$.action = strdup(proxy);
		if ($$.action == NULL)
				yyerror("Out of memory");
		free($3);
		free($5);
	}
		| flags PROXY ipaddr COLON STRING
	{
		char proxy[1024];
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_PROXY;
		$$.action = NULL;
		$$.aitop = NULL;
		$$.flags = $1;

		snprintf(proxy, sizeof(proxy), "%s:%s", addr_ntoa(&$3), $5);
		$$.action = strdup(proxy);
		if ($$.action == NULL)
				yyerror("Out of memory");
		free($5);
	}
		| FILTERED
	{
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_FILTERED;
		$$.action = NULL;
	}
		| CLOSED
	{
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_CLOSED;
		$$.action = NULL;
	}
		| flags OPEN
	{
		memset(&$$, 0, sizeof($$));
		$$.status = PORT_OPEN;
		$$.action = NULL;
		$$.flags = $1;
	}
;

template	: STRING
	{
		$$ = template_find($1);
		if ($$ == NULL)
			yyerror("Unknown template \"%s\"", $1);
		free($1);
	}
		| TEMPLATE
	{
		$$ = template_find("template");
		if ($$ == NULL)
			yyerror("Unknown template \"%s\"", "template");
	}
		| DEFAULT
	{
		$$ = template_find("default");
		if ($$ == NULL)
			yyerror("Unknown template \"%s\"", "default");
	}
		| ipaddr
	{
		$$ = template_find(addr_ntoa(&$1));
		if ($$ == NULL)
			yyerror("Unknown template \"%s\"", addr_ntoa(&$1));
	}
;
personality	: CMDSTRING
	{
		$1[strlen($1) - 1] = '\0';
		$$ = personality_find($1+1);
		if ($$ == NULL)
			yyerror("Unknown personality \"%s\"", $1+1);
		free($1);
	}
		| RANDOM
	{
		$$ = personality_random();
		if ($$ == NULL)
			yyerror("Random personality failed");
	}
;
rate		: FLOAT
	{
		$$ = $1;
	}
		| NUMBER
	{
		$$ = $1;
	}
;
latency		: /* empty */ { $$ = 0; }
		| LATENCY NUMBER MS
	{
		$$ = $2;
	}
;
packetloss	: /* empty */ { $$ = 0; }
		| LOSS rate
	{
		$$ = $2 * 100;
	}
;
bandwidth	: /* empty */ { $$ = 0; }
		| BANDWIDTH NUMBER NUMBER
	{
		$$ = $2 * $3;
	}
		| BANDWIDTH NUMBER
	{
		$$ = $2;
	}
;
randomearlydrop	: /* empty */ { memset(&$$, 0, sizeof($$)); }
		| DROP BETWEEN NUMBER MS DASH NUMBER MS
	{
		if ($6 <= $3)
			yyerror("Incorrect thresholds. First number needs to "
				"be smaller than second number.");
		$$.low = $3;
		$$.high = $6;
	}
;
option	        : OPTION STRING STRING NUMBER
	{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_int = $4;
		cfg.cfg_type = HD_CONFIG_INT;
		plugins_config_item_add($2, $3, &cfg);
		
		free($2); free($3);
	}
                | OPTION STRING STRING FLOAT
        {
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_flt = $4;
		cfg.cfg_type = HD_CONFIG_FLT;
		plugins_config_item_add($2, $3, &cfg);

		free($2); free($3);
        }
                | OPTION STRING STRING STRING
        {
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = $4;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add($2, $3, &cfg);

		free($2); free($3); free($4);
        }
/* Make file names work */
                | OPTION STRING STRING SLASH STRING
        {
		struct honeyd_plugin_cfg cfg;
		char path[MAXPATHLEN];

		snprintf(path, sizeof(path), "/%s", $5);

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = path;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add($2, $3, &cfg);

		free($2); free($3); free($5);
        }
;

ui : LIST TEMPLATE
{
	template_list_glob(buffer, "*");
}
	| LIST TEMPLATE CMDSTRING
{
	$3[strlen($3)-1] = '\0';

	template_list_glob(buffer, $3+1);

	free ($3);
}
	| LIST TEMPLATE STRING
{
	template_list_glob(buffer, $3);
}
	| LIST SUBSYSTEM
{
	template_subsystem_list_glob(buffer, "*");
}
	| LIST SUBSYSTEM STRING
{
	template_subsystem_list_glob(buffer, $3);
}
	| LIST SUBSYSTEM CMDSTRING
{
	$3[strlen($3)-1] = '\0';
	template_subsystem_list_glob(buffer, $3+1);
	free($3);
}
	| DEBUG STRING NUMBER
{
	if (strcasecmp($2, "fd") == 0) {
		yyprintf("%d: %d\n", $3, fdshare_inspect($3));
	} else if (strcasecmp($2, "trace") == 0) {
		struct evbuffer *evbuf = evbuffer_new();
		if (evbuf == NULL)
			err(1, "%s: malloc");

		trace_inspect($3, evbuf);

		yyprintf("%s", evbuffer_pullup(evbuf, -1));

		evbuffer_free(evbuf);
	} else {
		yyerror("Unsupported debug command: \"%s\"\n", $2);
	}
	free($2);
};

shared	: /* Empty */
{
	$$ = 0;
}
		| SHARED
{
	$$ = 1;
}
;

restart	: /* Empty */
{
	$$ = 0;
}
		| RESTART
{
	$$ = 1;
}
;

flags	: /* Empty */
{
	$$ = 0;
}
		| TARPIT
{
	$$ = PORT_TARPIT;
}
;

condition : SOURCE OS EQUAL CMDSTRING
	{
		pf_osfp_t fp;
		$4[strlen($4) - 1] = '\0';
		if ((fp = pfctl_get_fingerprint($4+1)) == PF_OSFP_NOMATCH)
			yyerror("Unknown fingerprint \"%s\"", $4+1);
		if (($$.match_arg = malloc(sizeof(fp))) == NULL)
			yyerror("Out of memory");
		memcpy($$.match_arg, &fp, sizeof(fp));
		$$.match = condition_match_osfp;
		$$.match_arglen = sizeof(fp);
		free ($4);
	}
		| SOURCE IP EQUAL ipaddr
	{
		if (($$.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy($$.match_arg, &$4, sizeof(struct addr));
		$$.match = condition_match_addr;
		$$.match_arglen = sizeof(struct addr);
	}
		| SOURCE IP EQUAL ipnet
	{
		if (($$.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy($$.match_arg, &$4, sizeof(struct addr));
		$$.match = condition_match_addr;
		$$.match_arglen = sizeof(struct addr);
	}
		| TIME timecondition
	{
		if (($$.match_arg = malloc(sizeof(struct condition_time))) == NULL)
			yyerror("Out of memory");
		memcpy($$.match_arg, &$2, sizeof(struct condition_time));
		$$.match = condition_match_time;
		$$.match_arglen = sizeof(struct condition_time);
	}
		| PROTO
	{
		if (($$.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy($$.match_arg, &$1, sizeof(int));
		$$.match = condition_match_proto;
		$$.match_arglen = sizeof(int);
	}
		| OTHERWISE
	{
		$$.match_arg = 0;
		$$.match = condition_match_otherwise;
		$$.match_arglen = 0;
	}
;

timecondition	: BETWEEN time DASH time
	{
		$$.tm_start = $2;
		$$.tm_end = $4;
	}
;

time		: NUMBER COLON NUMBER STRING
	{
		int ispm = -1;
		int hour, minute;

		if (strcmp($4, "am") == 0) {
			ispm = 0;
		} else if (strcmp($4, "pm") == 0) {
			ispm = 1;
		} else {
			yyerror("Bad time specifier, use 'am' or 'pm': %s", $4);
			break;
		}
		free ($4);

		hour = $1 + (ispm ? 12 : 0);
		minute = $3;

		memset(&$$, 0, sizeof($$));
		$$.tm_hour = hour;
		$$.tm_min = minute;
	}
		| CMDSTRING
	{
		char *time = $1 + 1;
		time[strlen(time)-1] = '\0';

		if (strptime(time, "%T", &$$) != NULL) {
			; /* done */
		} else if (strptime(time, "%r", &$$) != NULL) {
			; /* done */
		} else {
			yyerror("Bad time specification; use \"hh:mm:ss\"");
		}

		free($1);
	}
;
%%

static void
dhcp_template(struct template *tmpl, char *interface, char *mac_addr)
{
	struct interface *inter;
	struct template *newtmpl;
	struct addr addr;
	extern int need_dhcp;
	extern int need_arp;

	if (mac_addr == NULL && tmpl->ethernet_addr == NULL) {
		yyerror("Need an ethernet address for DHCP.");
		return;
	}

	/* Find the right interface */
	if ((inter = interface_find(interface)) == NULL) {
		yyerror("Interface \"%s\" does not exist.", interface);
		return;
	}
	if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
		yyerror("Interface \"%s\" does not support ARP.", interface);
		return;
	}

	/* Need to find a temporary IP address */
	if (template_get_dhcp_address(&addr) == -1) {
		yyerror("Failed to obtain temporary IP address.");
		return;
	}

	newtmpl = template_clone(addr_ntoa(&addr), tmpl, inter, 1);
	if (newtmpl == NULL) {
		yyerror("Binding to %s failed", addr_ntoa(&addr));
		return;
	}
	
	newtmpl->addrbits = inter->if_addrbits;

	if (mac_addr != NULL) {
		/*
		 * This is more complicated than it should be.
		 * 1. Remove existing ARP table entries.
		 * 2. Set new ethernet MAC address
		 * 3. Assign interface to template
		 * 4. Post new ARP table entry.
		 */
		template_remove_arp(newtmpl);

		newtmpl->ethernet_addr = ethernetcode_make_address(mac_addr);
		if (newtmpl->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", mac_addr);
		}

		newtmpl->inter = inter;

		/* We need to update the ARP binding */
		template_post_arp(newtmpl, &addr);
	}

	/* We can ignore the rest if we just verify the configuration */
	if (honeyd_verify_config)
		return;

	/* Wow - now we can assign the DHCP object to it */
	queue_dhcp_discover(newtmpl);

	need_arp = need_dhcp = 1;
}

int
yyerror(char *fmt, ...)
{
	va_list ap;
	errors = 1;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yywarn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yyprintf(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		vfprintf(stdout, fmt, ap);
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s", data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
parse_configuration(FILE *input, char *name)
{
	extern FILE *yyin;

	buffer = NULL;
	errors = 0;
	lineno = 1;
	filename = name;
	yyin = input;
	yyparse();
	return (errors ? -1 : 0);
}

/*
 * Parse from memory.  Error output is buffered
 */

int
parse_line(struct evbuffer *output, char *line)
{
	void *yybuf;

	buffer = output;
	errors = 0;
	lineno = 1;
	filename = "<stdin>";
	yybuf = yy_scan_string(line);
	yyparse();
	yy_delete_buffer(yybuf);
	return (errors ? -1 : 0);
}
