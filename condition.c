/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
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
#include <sys/wait.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dnet.h>
#include <ctype.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "condition.h"
#include "pfvar.h"
#include "osfp.h"

/*
 * Match an operating system (p0f) fingerprint
 */

int
condition_match_osfp(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen, void *arg)
{
	pf_osfp_t fp = *(pf_osfp_t *)arg;

	return (honeyd_osfp_match(ip, fp));
}

/*
 * Match the source address of a machine
 */

int
condition_match_addr(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen, void *arg)
{
	struct addr *tmp = arg;
	struct addr addr_start, addr_end, src;

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	addr_start = *tmp;
	addr_start.addr_bits = IP_ADDR_BITS;

	addr_bcast(tmp, &addr_end);
	addr_end.addr_bits = IP_ADDR_BITS;

	if (addr_cmp(&src, &addr_start) < 0)
		return (0);
	if (addr_cmp(&src, &addr_end) > 0)
		return (0);

	return (1);
}

/*
 * Match the IP protocol of the packet
 */

int
condition_match_proto(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen, void *arg)
{
	int *proto = arg;
	return (ip->ip_p == *proto);
}

/*
 * Match anything
 */

int
condition_match_otherwise(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen, void *arg)
{
	return 1;
}

static int
daysec(const struct tm *tm)
{
	int seconds;

	seconds = (tm->tm_hour * 60 + tm->tm_min) * 60 + tm->tm_sec;

	return (seconds);
}

/*
 * Match the time of access
 */

int
condition_match_time(const struct template *tmpl, const struct ip_hdr *ip,
    u_short iplen, void *arg)
{
	time_t tmp;
	struct tm now;
	int start_sec, now_sec, end_sec;
	struct timeval tv;
	struct condition_time *cdt = arg;

	gettimeofday(&tv, NULL);

	tmp = tv.tv_sec; localtime_r(&tmp, &now);

	start_sec = daysec(&cdt->tm_start);
	now_sec = daysec(&now);
	end_sec = daysec(&cdt->tm_end);
	
	return (start_sec <= now_sec && now_sec <= end_sec);
}
