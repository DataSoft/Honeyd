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
%x incl

%{
#include <sys/types.h>
#include <sys/tree.h>
#include <syslog.h>
#include "config.h"

#include <sys/queue.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <dnet.h>

#include <event.h>

#include "honeyd.h"
#include "router.h"
#include "personality.h"
#include "plugins_config.h"
#include "condition.h"
#include "parse.h"

int hyderror(char *fmt, ...);
#define yyerror hyderror

extern int lineno;
extern char *filename;
extern int curtype;

#define MAX_INCLUDE_DEPTH 10

YY_BUFFER_STATE includes[MAX_INCLUDE_DEPTH];
int linenos[MAX_INCLUDE_DEPTH];
char *filenames[MAX_INCLUDE_DEPTH];
int includes_index = 0;

%}

%%
create		{ return CREATE; }
add		{ return ADD; }
port		{ return PORT; }
bind		{ return BIND; }
clone		{ return CLONE; }
filtered		{ return FILTERED; }
open		{ return OPEN; }
closed		{ return CLOSED; }
default		{ return DEFAULT; }
action		{ return ACTION; }
set		{ return SET; }
personality	{ return PERSONALITY; }
random		{ return RANDOM; }
annotate	{ return ANNOTATE; }
no		{ return NO; }
finscan		{ return FINSCAN; }
fragment	{ return FRAGMENT; }
drop		{ return DROP; }
old		{ return OLD; }
new		{ return NEW; }
proxy		{ return PROXY; }
broadcast {return BROADCAST;}
uptime		{ return UPTIME; }
droprate	{ return DROPRATE; }
in		{ return IN; }
syn		{ return SYN; }
uid		{ return UID; }
gid		{ return GID; }
route		{ return ROUTE; }
entry		{ return ENTRY; }
net		{ return NET; }
link		{ return LINK; }
unreach		{ return UNREACH; }
latency		{ return LATENCY; }
bandwidth	{ return BANDWIDTH; }
Kbps		{ yylval.number = 1000; return NUMBER; }
Mbps		{ yylval.number = 1000000; return NUMBER; }
ms		{ return MS; }
loss		{ return LOSS; }
subsystem	{ return SUBSYSTEM; }
template	{ return TEMPLATE; }
option		{ return OPTION; }
to		{ return TO; }
on		{ return ON; }
dhcp		{ return DHCP; }
shared		{ return SHARED; }
restart		{ return RESTART; }
network		{ return NETWORK; }
tunnel		{ return TUNNEL; }
tarpit		{ return TARPIT; }
spoof		{ return SPOOF; }
from		{ return FROM; }
delete		{ return DELETE; }
tcp		{ yylval.number = IP_PROTO_TCP;
		  curtype = SOCK_STREAM; return PROTO; }
udp		{ yylval.number = IP_PROTO_UDP;
		  curtype = SOCK_DGRAM; return PROTO; }
icmp		{ yylval.number = IP_PROTO_ICMP; return PROTO; }
dynamic		{ return DYNAMIC; }
source		{ return SOURCE; }
list		{ return LIST; }
ip		{ return IP; }
os		{ return OS; }
use		{ return USE; }
if		{ return IF; }
otherwise	{ return OTHERWISE; }
between		{ return BETWEEN; }
time		{ return TIME; }
internal	{ return INTERNAL; }
maxfds		{ return MAXFDS; }
ethernet	{ return ETHERNET; }
debug		{ return DEBUG; }
include		{ BEGIN(incl); }
<incl>[ \t]*      /* eat the whitespace */
<incl>[^ \t\n]+	{ /* got the include file name */
		  if (includes_index >= MAX_INCLUDE_DEPTH) {
			  yyerror("Includes nested too deeply");
			  exit(1);
		  }

		  linenos[includes_index] = lineno;
		  filenames[includes_index] = filename;
		  includes[includes_index++] = YY_CURRENT_BUFFER;
		  if ((yyin = fopen(yytext, "r")) == NULL) {
			yyerror("Can not open \"%s\"", yytext);
			exit(1);
		  }
		  filename = strdup(yytext);
		  lineno = 1;
		  yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));

                  BEGIN(INITIAL);
		}
<<EOF>>		{
		  if (--includes_index < 0)
			  yyterminate();
		  else {
			  free(filenames[includes_index + 1]);
			  filename = filenames[includes_index];
			  lineno = linenos[includes_index];
			  yy_delete_buffer(YY_CURRENT_BUFFER);
			  yy_switch_to_buffer(includes[includes_index]);
		  }
		}
[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+  { yylval.string = strdup(yytext); return IPSTRING; }
[0-9]+		{ yylval.number = atoi(yytext); return NUMBER; }
[0-9]+\.[0-9]+  { yylval.floatp = atof(yytext); return FLOAT; }
[\$A-Za-z][\.\(\)\/A-Za-z_\-0-9\*]* { yylval.string = strdup(yytext); return STRING; }
\"[^\"]+\" { yylval.string = strdup(yytext); return CMDSTRING; }
\.		{ return DOT; }
"-"		{ return DASH; }
"="		{ return EQUAL; }
:		{ return COLON; }
\/		{ return SLASH; }
\        { ; }
\n       { lineno++;}
\t       { ; }
"#".*\n { lineno++; }
.        { yyerror("illegal token"); }
%%
#ifndef hydwrap
int hydwrap() { return 1; }
#endif
