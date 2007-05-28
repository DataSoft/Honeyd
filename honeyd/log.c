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

#include <sys/param.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dnet.h>
#include <ctype.h>
#include <syslog.h>
#include <netdb.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "osfp.h"
#include "log.h"

static char *
honeyd_logtuple(const struct tuple *hdr)
{
	static char buf[128];
	char asrc[24], adst[24];
	struct addr src, dst;
	ushort sport, dport;
	
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);

	if (hdr->local) {
		struct addr tmp;

		tmp = src;
		src = dst;
		dst = tmp;
		sport = hdr->dport;
		dport = hdr->sport;
	} else {
		sport = hdr->sport;
		dport = hdr->dport;
	}


	addr_ntop(&src, asrc, sizeof(asrc));
	addr_ntop(&dst, adst, sizeof(adst));

	if (hdr->type == SOCK_STREAM || hdr->type == SOCK_DGRAM)
		snprintf(buf, sizeof(buf), "%s %d %s %d",
		    asrc, sport, adst, dport);
	else if (hdr->type == SOCK_RAW)
		snprintf(buf, sizeof(buf), "%s %s: %d(%d)",
		    asrc, adst, hdr->sport, hdr->dport);
	else
		snprintf(buf, sizeof(buf), "%s %s", asrc, adst);
		

	return (buf);
}

static char *
honeyd_logtime(void)
{
	static char logtime[32];
	struct timeval tv;
	struct tm *tm;
	time_t seconds;

	if (gettimeofday(&tv, NULL) == -1)
		err(1, "%s: gettimeofday", __func__);
	seconds = tv.tv_sec;
	
	/* ctime returns 26-character string */
	tm = localtime(&seconds);
	snprintf(logtime, sizeof(logtime),
	    "%04d-%02d-%02d-%02d:%02d:%02d.%04d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    (int)(tv.tv_usec / 100));

	return (logtime);
}

char *
honeyd_logdate(void)
{
	static char logtime[32];
	struct timeval tv;
	struct tm *tm;
	time_t seconds;

	if (gettimeofday(&tv, NULL) == -1)
		err(1, "%s: gettimeofday", __func__);
	seconds = tv.tv_sec;
	
	/* ctime returns 26-character string */
	tm = localtime(&seconds);
	snprintf(logtime, sizeof(logtime),
	    "%04d-%02d-%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	return (logtime);
}

static char *
honeyd_logproto(int proto)
{
	static char protoname[32];

	struct protoent *pe;
	struct protoent tcp = { "tcp", NULL, IP_PROTO_TCP };
	struct protoent udp = { "udp", NULL, IP_PROTO_UDP };
	struct protoent icmp = { "icmp", NULL, IP_PROTO_ICMP };

	switch(proto) {
	case IP_PROTO_TCP:
		pe = &tcp;
		break;
	case IP_PROTO_UDP:
		pe = &udp;
		break;
	case IP_PROTO_ICMP:
		pe = &icmp;
		break;
	default:
		/* Reads a file and is very slow */
		pe = getprotobynumber(proto);
		break;
	}

	if (pe == NULL)
		snprintf(protoname, sizeof(protoname), "unkn(%d)", proto);
	else
		snprintf(protoname, sizeof(protoname), "%s(%d)",
		    pe->p_name, proto);

	return (protoname);
}

#define TESTFLAG(x,y) do { \
	if (flags & (x)) \
		tcpflags[i++] = (y); \
} while (0)

static char *
honeyd_logtcpflags(int flags)
{
	static char tcpflags[11];
	int i = 1;

	tcpflags[0] = ' ';
	TESTFLAG(TH_FIN, 'F');
	TESTFLAG(TH_SYN, 'S');
	TESTFLAG(TH_RST, 'R');
	TESTFLAG(TH_PUSH, 'P');
	TESTFLAG(TH_ACK, 'A');
	TESTFLAG(TH_URG, 'U');
	TESTFLAG(TH_ECE, 'E');
	TESTFLAG(TH_CWR, 'C');

	tcpflags[i] = '\0';

	return (tcpflags);
}

FILE *
honeyd_logstart(const char *filename)
{
	FILE *logfp;
	char *logtime;

	logfp = fopen(filename, "a");
	if (logfp == NULL) {
		syslog(LOG_WARNING, "%s: fopen(\"%s\"): %m", __func__, filename);
		return (NULL);
	}

	/* Line buffered I/O */
	setvbuf(logfp, NULL, _IOLBF, 0);

	logtime = honeyd_logtime();
	fprintf(logfp, "%s honeyd log started ------\n", logtime);

	return (logfp);
}

static char *
honeyd_log_comment(int proto, const struct tuple *hdr, const char *remark)
{
	static char comment[256];
	struct ip_hdr ip;
	char *name;
	
	comment[0] = '\0';

	ip.ip_src = hdr->ip_src;
	name = honeyd_osfp_name(&ip);
	if (name != NULL)
		snprintf(comment, sizeof(comment), " [%s]", name);
	if (remark != NULL)
		strlcat(comment, remark, sizeof(comment));

	return (comment);
}

void
honeyd_logend(FILE *logfp)
{
	char *logtime;

	if (logfp == NULL)
		return;

	logtime = honeyd_logtime();
	fprintf(logfp, "%s honeyd log stopped ------\n", logtime);

	fclose(logfp);
}

void
honeyd_log_service(FILE *fp, int proto, const struct tuple *hdr,
    const char *line)
{
	static char myline[1024];
	char *p;
	int len;

	syslog(LOG_NOTICE, "E%s: %s", honeyd_contoa(hdr), line);

	if (fp == NULL)
		return;

	do {
		len = sizeof(myline);
		p = strchr(line, '\n');
		if (p != NULL) {
			if ((int)(p - line) < sizeof(myline))
				len = (int)(p - line) + 1;
		}
		strlcpy(myline, line, len);

		if (p != NULL)
			line = ++p;

		fprintf(fp, "%s %s %s: |%s|\n",
		    honeyd_logtime(),
		    honeyd_logproto(proto),
		    honeyd_logtuple(hdr),
		    myline);
	} while (p != NULL && *p);
}

void
honeyd_log_probe(FILE *fp, int proto, const struct tuple *hdr,
    int size, int flags, const char *comment)
{
	if (fp == NULL)
		return;

	fprintf(fp, "%s %s - %s: %d%s%s\n",
	    honeyd_logtime(),
	    honeyd_logproto(proto),
	    honeyd_logtuple(hdr),
	    size,
	    proto == IP_PROTO_TCP ? honeyd_logtcpflags(flags) : "",
	    honeyd_log_comment(proto, hdr, comment));
}

void
honeyd_log_flownew(FILE *fp, int proto, const struct tuple *hdr)
{
	char *tuple, *logtime, *protoname;

	if (fp == NULL)
		return;

	logtime = honeyd_logtime();
	tuple = honeyd_logtuple(hdr);
	protoname = honeyd_logproto(proto);
	fprintf(fp, "%s %s S %s%s\n",
	    logtime, protoname, tuple,
	    honeyd_log_comment(proto, hdr, NULL));
}

void
honeyd_log_flowend(FILE *fp, int proto, const struct tuple *hdr)
{
	char *tuple, *logtime, *protoname;

	if (fp == NULL)
		return;

	logtime = honeyd_logtime();
	tuple = honeyd_logtuple(hdr);
	protoname = honeyd_logproto(proto);
	fprintf(fp, "%s %s E %s: %d %d\n", logtime, protoname, tuple,
	    hdr->received, hdr->sent);
}
