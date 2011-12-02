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
#include <sys/wait.h>

#include <math.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dnet.h>
#include <ctype.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "xprobe_assoc.h"
#include "template.h"
#include "debug.h"

/* ET - Moved SPLAY_HEAD to personality.h so xprobe_assoc.c could use it. */
int npersons;

/* ET - global from honeyd.c */
struct personate person_drop = {};
static struct event personality_time_ev;
static struct timeval tv_periodic;

SPLAY_GENERATE(perstree, personality, node, perscompare);

/* ET - For the Xprobe fingerprint tree */
SPLAY_GENERATE(xp_fprint_tree, xp_fingerprint, node, xp_fprint_compare);

static void
personality_time_evcb(int fd, short what, void *arg)
{
	struct event *ev = arg;
	struct timeval tv;

	gettimeofday(&tv_periodic, NULL);

	timerclear(&tv);
	tv.tv_usec = 100000;	/* every 100 ms */
	evtimer_add(ev, &tv);
}

void
xprobe_personality_init(void)
{
  SPLAY_INIT(&xp_fprints);
}

void
personality_init(void)
{
	npersons = 0;
	SPLAY_INIT(&personalities);

	/* Start a timer that keeps track of the current system time */
	evtimer_set(&personality_time_ev,
	    personality_time_evcb, &personality_time_ev);
	personality_time_evcb(-1, EV_TIMEOUT, &personality_time_ev);
}

struct personality *
personality_new(const char *name)
{
	struct personality *pers, tmp;

	tmp.name = (char *)name;
	if (SPLAY_FIND(perstree, &personalities, &tmp))
		return (NULL);

	if ((pers = calloc(1, sizeof(struct personality))) == NULL)
		err(1, "%s: calloc", __FUNCTION__);

	if ((pers->name = strdup(name)) == NULL)
		err(1, "%s: stdup", __FUNCTION__);

	/* Initialize defaults */
	pers->tstamphz = -1;

	npersons++;
	SPLAY_INSERT(perstree, &personalities, pers);

	/* Find and add the Xprobe fingerprint, if it exists */
	correlate_nmap_with_xprobe(pers);

	return (pers);
}

struct personality *
personality_clone(const struct personality *person)
{
	struct personality *newperson;

	if ((newperson = malloc(sizeof(struct personality))) == NULL)
		err(1, "%s: malloc", __FUNCTION__);

	memcpy(newperson, person, sizeof(struct personality));

	return (newperson);
}

/*
 * Frees the reference that a template has to a personality.
 */

void
personality_declone(struct personality *pers)
{
	free(pers);
}

void
personality_free(struct personality *pers)
{
	SPLAY_REMOVE(perstree, &personalities, pers);

	free(pers->name);
	free(pers);
}

struct personality *
personality_random(void)
{
	extern rand_t *honeyd_rand;
	struct personality *pers;
	int i;

	if (!npersons)
		return (NULL);

	i = rand_uint32(honeyd_rand) % npersons;
	pers = SPLAY_MIN(perstree, &personalities);
	while (i--) {
		pers = SPLAY_NEXT(perstree, &personalities, pers);
	}

	return (pers);
}

struct personality *
personality_find(const char *name)
{
	struct personality tmp;
	tmp.name = (char *)name;
	return (SPLAY_FIND(perstree, &personalities, &tmp));
}

/* Not much here, set up ip id accordingly */

void
ip_personality(struct template *tmpl, uint16_t *pid, enum ipid_protocol proto)
{
	extern rand_t *honeyd_rand;
	struct personality *person;

	if (tmpl == NULL)
		return;
	if ((person = tmpl->person) == NULL)
		return;

	int *ipid_cached, *ipid_cached_TCP, *ipid_cached_ICMP;
	//If it's a shared sequence...
	if( person->ipid_shared_sequence == 1 )
	{
		ipid_cached_TCP = &tmpl->ipid;
		ipid_cached_ICMP = &tmpl->ipid;
	}
	else
	{
		ipid_cached_TCP = &tmpl->IPID_last_TCP;
		ipid_cached_ICMP = &tmpl->IPID_last_ICMP;
	}

	enum ipidtype ourType;
	if( proto == TCP_UDP)
	{
		//TODO: What are we supposed to do with the CI test? It's unused. Also, we're assuming UDP
		//	should be handled the same as TCP.
		ourType = person->IPID_type_TI;
		ipid_cached = ipid_cached_TCP;
	}
	else
	{
		ourType = person->IPID_type_II;
		ipid_cached = ipid_cached_ICMP;
	}

	while (!*ipid_cached)
		*ipid_cached = rand_uint16(honeyd_rand);

	switch(ourType)
	{
		case(ID_SEQUENTIAL):
		{
			*pid = *ipid_cached++;
			break;
		}
		case(ID_SEQUENTIAL_BROKEN):
		{
			*pid = htons(*ipid_cached++);
			break;
		}
		case(ID_ZERO):
		{
			*pid = 0;
			break;
		}
		case(ID_RPI):
		{
			/* Apparently needs to be at least 1000 */
			*ipid_cached += 1000 + (rand_uint16(honeyd_rand) % 1024);
			*pid = *ipid_cached;
			break;
		}
		case(ID_CONSTANT):
		{
			*pid = *ipid_cached;
			break;
		}
		case(ID_RANDOM):
		{
			*pid = rand_uint16(honeyd_rand);
			break;
		}
	}
}

struct personate *
tcp_personality_test(const struct tcp_con *con, struct personality *person,
    uint8_t sndflags)
{
	uint8_t flags;

	/* ET - The T1 test of NMAP has the SYN and ECE TCP flags set.  The T5
         * test of NMAP has only the SYN TCP flag set.  The sequence number
         * test of NMAP has only the SYN TCP flag set.
	 * Niels: We reuse the T1 even if ECE is not set if the response seems
	 * sane.  This allows us to get TCP options right, too.
	 */
        
	flags = con->rcv_flags & (TH_FIN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_SYN);
	if (flags == TH_SYN) {
		int hasece = con->rcv_flags & TH_ECE;

		switch (con->state) {
		case TCP_STATE_LISTEN:
		case TCP_STATE_SYN_RECEIVED: {
			struct personate *test = &person->t_tests[0];
			if (sndflags & TH_RST) 
				return (NULL);
			
			/* Check if we can use the ECE response for normal
			 * SYN, too.
			 */
			if (hasece || (test->flags == (TH_SYN|TH_ACK) &&
				test->forceack == ACK_KEEP))
				return (test);

			return (NULL);
		}
		case TCP_STATE_CLOSED:
			if (hasece)
				return (NULL);
			return (&person->t_tests[4]);
		default:
			return (NULL);
		}
	} else if (flags == 0) {
		switch (con->state) {
		case TCP_STATE_LISTEN:
			return (&person->t_tests[1]);
		default:
			return (NULL);
		}
	} else if (flags == (TH_SYN|TH_PUSH|TH_FIN|TH_URG)) {
		switch (con->state) {
		case TCP_STATE_LISTEN:
		case TCP_STATE_SYN_RECEIVED:
			return (&person->t_tests[2]);
		default:
			return (NULL);
		}
	} else if (flags == TH_ACK) {
		switch (con->state) {
		case TCP_STATE_LISTEN:
		case TCP_STATE_SYN_RECEIVED:
			return (&person->t_tests[3]);
		case TCP_STATE_CLOSED:
			return (&person->t_tests[5]);
		default:
			return (NULL);
		}
	} else if (flags == (TH_FIN|TH_PUSH|TH_URG)) {
		switch (con->state) {
		case TCP_STATE_CLOSED:
			return (&person->t_tests[6]);
		default:
			return (NULL);
		}
	} else if ((flags & TH_FIN) && (flags & (TH_SYN|TH_ACK)) == 0) {
		/*
		 * If we get a FIN flag and do not allow fin scanning, then
		 * we just let the regular state engine run its course.
		 * Otherwise, we silently drop the packet, which indicates
		 * that FIN scanning is allowed for TCP_STATE_LISTEN.
		 */
		if (person->disallow_finscan || con->state != TCP_STATE_LISTEN)
			return (NULL);
		return (&person_drop);
	}

	return (NULL);
}

//Retrieved from: http://en.literateprograms.org/Box-Muller_transform_(C)?oldid=7011
double rand_normal(double mean, double stddev)
{
    static double n2 = 0.0;
    static int n2_cached = 0;
    if (!n2_cached) {
        double x, y, r;
	do {
	    x = 2.0*rand()/RAND_MAX - 1;
	    y = 2.0*rand()/RAND_MAX - 1;

	    r = x*x + y*y;
	} while (r == 0.0 || r > 1.0);

        {
        double d = sqrt(-2.0*log(r)/r);
	double n1 = x*d;
	n2 = y*d;

        double result = n1*stddev + mean;

        n2_cached = 1;
        return result;
        }
    } else {
        n2_cached = 0;
        return n2*stddev + mean;
    }
}


/* This function computes ISNs for TD and RI.
 *
 * NMAP obtains six initial sequence number (ISN) samples when performing
 * an OS scan.  Most of the calculations for sequence number prediction
 * is based upon the differences of consecutive ISNs.  Thus there are
 * five sample differences.  If the differences are determined not be
 * be CONSTANT, RANDOM, Multiple of 64000, or Multiple of 800, statistical
 * calculations are performed on the differences.  The remaining cases, 
 * TRIVIALTIME (or time dependent) and RI (random increment) are dealt
 * with in this function.
 *
 * NMAP computes the greatest common denominator (GCD) and a slightly
 * modified standard deviation (modified so-as to prevent floating-point
 * calculations to be rounded down to zero, which is not as useful) of the
 * differences in the ISNs.  This function is the reverse, computing
 * ISNs which will produce a valid GCD and standard deviation for NMAP
 * to match to a fingerprint.
 *
 * First, if the standard deviation is zero, then the difference in ISNs
 * is constant.  The set of five differences whose GCD is X, and whose
 * standard deviation is not zero is { X, X, X, X, 2X }.  The NMAP
 * fingerprints file gives a valid range for the standard deviation.  If
 * no X can produce a standard deviation in the given range, then it is
 * assumed that the standard deviation must be zero. Mathematically, this
 * is the case if X > (2.5 + sqrt(simax^2 - simax)).  Unfortunately, this
 * series does not allow the ability to make sure the series is within
 * certain standard deviation range.
 *
 * Another less noticable, but less reliable way to generate a set of
 * five differences is to use a set
 *   { (A-1)X, (2A-1)X, (3A-1)X, (4A-1)X, (5A-1)X }
 * whose GCD is X, and the value of the integer A can be found to make
 * sure the standard deviation of the five numbers is within a given
 * range.  The range is Amin < A < Amax, where
 *   Amin = sqrt(simin * simin - simin) / 2) / X
 *   Amax = sqrt(simax * simax - simax) / 2) / X
 * One selects an integer in this range for the value of A, plugs the
 * number into the set of differences, and then adds the differences, in
 * order, to the previous ISN, looping around when all five differences
 * have been used.  Because the set of numbers is not optimal there are
 * cases when Amax - Amin < 1, in which case an integer in between 
 * Amin and Amax may not be able to be found.  In this case, the only
 * way to generate the ISN is to use constant differences, whose standard
 * deviation is zero.
 *
 * This discussion is a very short version of how this function generates
 * ISNs.
 */

static uint32_t
get_next_isn(struct template *tmpl, const struct personality *person)
{
	double mean, std_dev;

	/* if SEQ is constant */
	if(person->TCP_ISR_max == 0)
	{
		//Do nothing
		return (tmpl->seq);
	}

	//Nmap saves the values as binary log times 8, so undo this.
	//	(Supposedly, Nmap does this to prevent floating point rounding during calculations)
	mean = pow(2,((double)person->TCP_ISR / 8));
	std_dev = pow(2,((double)person->TCP_SP / 8));

	return rand_normal(mean, std_dev);

}

#define TIME_CORRECT(x,y) do { \
	(y)->tv_sec = 0; \
	(y)->tv_usec = (y)->tv_usec % (x); \
	timersub(&tmpl->tv, y, &tmpl->tv); \
} while (0)

/* Get the correct time for this personality */

void
personality_time(struct template *tmpl, struct timeval *diff)
{
	uint32_t ms;

	timersub(&tv_periodic, &tmpl->tv_real, diff);
	tmpl->tv_real = tv_periodic;

	ms = diff->tv_sec * 10000 + (diff->tv_usec / 100);
	ms *= tmpl->drift;

	diff->tv_sec = ms / 10000;
	diff->tv_usec = (ms % 10000) * 100;

	timeradd(&tmpl->tv, diff, &tmpl->tv);
}

int
tcp_personality_time(struct template *tmpl, struct timeval *diff)
{
	extern rand_t *honeyd_rand;
	struct personality *person = tmpl->person;
	int slowhz;

	if (person == NULL)
		return (-1);

	personality_time(tmpl, diff);

	if (person->tstamphz) {
		int tstamphz = person->tstamphz;
		int ticks;

		if (tstamphz == -1)
			tstamphz = 2;

		/* 
		 * Adjust so that the remaining subsecond ticks get
		 * counted next time.
		 */
		ticks = 1000000L / tstamphz;
		slowhz = diff->tv_sec * tstamphz + diff->tv_usec / ticks;
		TIME_CORRECT(ticks, diff);

		tmpl->timestamp += slowhz;
	} else {
		/*
		 * This is not the default.  Some stacks don't have
		 * any notion of time.
		 */
		slowhz = 0;
		tmpl->timestamp = 0;
	}

	/* 
	 * This is where new ISNs are generated.  The latest ISN is
	 * stored in tmpl->seq.  tmpl->seqcalls is the number of ISNs
	 * generated so far.
	 */

	/* if constant SEQ. IE: gcd == 0 */
	if( person->TCP_ISN_gcd_max == 0 )
	{
		/* do nothing to tmpl->seq */
		return (slowhz);
	}
	/* If random TCP ISNs IE: low gcd */
	else if( person->TCP_ISN_gcd_max < 11 )
	{
		/* No time component.  May be required for high latency */
		if (diff->tv_sec > 2) {
			uint32_t adjust, randGCD;

			/* pick a random number between TCP_ISN_gcd_min and TCP_ISN_gcd_max */
			uint32_t TCP_ISN_gcd_delta = person->TCP_ISN_gcd_max - person->TCP_ISN_gcd_min;
			randGCD = (rand_uint32(honeyd_rand) % TCP_ISN_gcd_delta) + person->TCP_ISN_gcd_min;

			adjust = rand_uint32(honeyd_rand) % 2048;
			adjust *= (slowhz - 2) * randGCD;
			tmpl->seq += adjust;
		}
	}
	else
	{
		/* if not random, just increment the SEQ by the GCD */
		tmpl->seq += slowhz * person->TCP_ISN_gcd_min;
	}

	return (slowhz);
}

uint32_t
tcp_personality_seq(struct template *tmpl, struct personality *person)
{
	struct timeval tmp;
	extern rand_t *honeyd_rand;
	int slowhz;

	tmpl->seqcalls++;

	if (!timerisset(&tmpl->tv))
	{
		gettimeofday(&tv_periodic, NULL);
		tmpl->tv_real = tmpl->tv = tv_periodic;
		if (tmpl->timestamp == 0)
		{
			tmpl->timestamp = rand_uint32(honeyd_rand) % 1728000;
		}
		if (tmpl->seq == 0)
		{
			if (person->TCP_ISN_gcd_max == 0 && person->valset)
				tmpl->seq = person->TCP_ISN_constant_val;
			else
				tmpl->seq = rand_uint32(honeyd_rand);
		}
		return (tmpl->seq);
	}

	slowhz = tcp_personality_time(tmpl, &tmp);

	/* 
	 * This is where new ISNs are generated.  The latest ISN is
	 * stored in tmpl->seq.  tmpl->seqcalls is the number of ISNs
	 * generated so far.
	 */

	tmpl->seq = get_next_isn(tmpl, person);
	return (tmpl->seq);

}

/* Default TCP options is timestamp, noop, noop */
static char *default_opts = "tnn";

int
tcp_personality_match(struct tcp_con *con, int flags)
{
	struct template *tmpl = con->tmpl;
	struct personality *person;

	/* Find template and corresponding personality */
	if (tmpl == NULL)
		return (0);
	person = tmpl->person;
	if (person == NULL)
		return (0);

	return (tcp_personality_test(con, person, flags) != NULL);
}

int
tcp_personality(struct tcp_con *con, uint8_t *pflags, int *pwindow, int *pdf,
    uint16_t *pid, char **poptions)
{
	struct template *tmpl = con->tmpl;
	struct personality *person;
	struct personate *pers;
	uint8_t flags = *pflags;

	if (poptions != NULL)
		*poptions = NULL;

	/* XXX - We need to find some template to use here */

	/* Find template and corresponding personality */
	if (tmpl == NULL)
		return (-1);
	person = tmpl->person;
	if (person == NULL)
		return (-1);

	if ((pers = tcp_personality_test(con, person, flags)) == NULL) {
		/* Not a test case - but we still want to pretend */
		ip_personality(tmpl, pid, TCP_UDP);

		/* Set the sequence number only on SYN segments */
		if (con->snd_una == 0 && (flags & TH_SYN))
			con->snd_una = tcp_personality_seq(tmpl, person);

		/* If we support timestamps, always set them */
		if (person->tstamphz >= 0 && poptions != NULL)
			*poptions = default_opts;
		return (-1);
	}

	*pwindow = pers->window;
	*pflags = pers->flags;
	*pdf = pers->df;
	if (poptions != NULL)
		*poptions = pers->options;

	switch (pers->forceack) {
	case ACK_ZERO:
		con->rcv_next = 0;
		break;
	case ACK_DECREMENT:
		con->rcv_next--;
		break;
	case ACK_KEEP:
		break;
	}

	ip_personality(tmpl, pid, TCP_UDP);

	if (con->snd_una == 0)
		con->snd_una = tcp_personality_seq(tmpl, person);

	return (0);
}

#define SET(y, x, w, l) do { \
	(x)->opt_type = w; \
	(x)->opt_len = l; \
	memcpy(y, x, l); \
} while (0)

/* 
 * Given a character string that describe TCP options, create the
 * corresponding packet data.
 */

void
tcp_personality_options(struct tcp_con *con, struct tcp_hdr *tcp,
    char *options)
{
	extern rand_t *honeyd_rand;
	u_char *p = (u_char *)tcp + TCP_HDR_LEN;
	struct template *tmpl = con->tmpl;
	struct tcp_opt opt;
	int optlen = 0, simple = 0;
	uint32_t timestamp;
	short mss = 1460;
	char *o;
	
	for (o = options; *o; o++) {
		opt.opt_len = 0;
		switch(*o) {
		case 'm':
			if (o[1] == 'e') {
				o++;
				if (con->mss)
					mss = con->mss;
			}
			if (con->flags & TCP_TARPIT)
				mss = 64;
			opt.opt_data.mss = htons(mss);
			SET(p, &opt, TCP_OPT_MSS, 4);
			break;
		case 'w':
			opt.opt_data.wscale = 0;
			SET(p, &opt, TCP_OPT_WSCALE, 3);
			break;
		case 't':
			if (tmpl != NULL) {
				struct timeval tv;
				tcp_personality_time(tmpl, &tv);
				timestamp = htonl(tmpl->timestamp);
			} else {
				timestamp = rand_uint32(honeyd_rand);
			}
			opt.opt_data.timestamp[0] = timestamp;
			opt.opt_data.timestamp[1] = 0;
			if (con->sawtimestamp)
				opt.opt_data.timestamp[1] = con->echotimestamp;
			SET(p, &opt, TCP_OPT_TIMESTAMP, 2 + 4 + 4);
			break;
		case 'n':
			simple++;
			SET(p, &opt, TCP_OPT_NOP, 1);
			break;
		case 'l':
			SET(p, &opt, TCP_OPT_EOL, 2);
			break;
		default:
			opt.opt_len = 0;
			break;
		}
		optlen += opt.opt_len;
		p += opt.opt_len;
	}

	/* Check if we have only unreasonable options */
	if (simple == optlen)
		optlen = 0;

	if (optlen)
		tcp->th_off += (optlen + 3) / 4;
}

/* JVR - added '+1' in default case below for situations where IP checksum does not
   change after byte order conversion, e.g. IP checksum of 0x6565.
   Also added missing 'break' statement in RVAL_ZERO case  */
#define RVAL_DO(x, w) do { \
	switch (w) { \
	case RVAL_OKAY: break; \
	case RVAL_ZERO: (x) = 0; break; \
	default: (x) = ntohs(x+1); \
	} \
} while (0)

int
icmp_error_personality(struct template *tmpl,
    struct addr *dst, struct ip_hdr *ip, uint8_t *pdf,
    uint8_t *ptos, int *pquotelen, uint8_t *ttl)
{
	struct persudp *test;
	int iphdr_changed = 0;
	struct xp_fingerprint *xp_print;

	if (tmpl == NULL || tmpl->person == NULL)
		return (1);

	/* JVR - set TTL using XP fingerprint, use nmap for rest of header settings */
	xp_print = tmpl->person->xp_fprint;

	if (xp_print != NULL)
		*ttl = xp_print->ttl_vals.icmp_unreach_reply_ttl.ttl_val;
	/* JVR */

	test = &tmpl->person->udptest;

	if (!test->response)
		return (0);

	*pdf = test->df;
	*ptos = test->tos;
	*pquotelen = test->quotelen;
	if (test->riplen) {
		u_int len = ntohs(ip->ip_len);
		ip->ip_len = htons(len + test->riplen);
		iphdr_changed = 1;
	}

	RVAL_DO(ip->ip_id, test->rid);
	if (test->rid != RVAL_OKAY)
		iphdr_changed = 1;

	/* We need to recompute the ip header checksum in some cases */
	if (test->ripck == RVAL_OKAY) {
		if (iphdr_changed)
			ip_checksum(ip, ip->ip_hl << 2);
	} else
		RVAL_DO(ip->ip_sum, test->ripck);

	if (ip->ip_p == IP_PROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
		u_char *p = (u_char *)(udp + 1);
		RVAL_DO(udp->uh_sum, test->uck);
		if (test->dat == RVAL_BAD)
			*p = 0;
	}
	
	return (1);
}

/* Parse nmap tests */

/*
 * Improve TCP ISN calculation by reading all possible
 * gcd values and selecting the smallest one.
 */

void
parse_seq_gcd(char *s, char *end, struct personality *pers)
{
	char *next, *endptr, *quantifier, *secondValue;
	unsigned int val, minval;
	int orexp;

	orexp = val = 0;
	endptr = quantifier = NULL;
	minval = UINT_MAX;

	/* Determine if the values are or'd or and'd */
	if (*s && strpbrk(s, "|") != NULL)
		orexp = 1;

	/* Go through all &'d and |'d values */
	while (s < end && s != NULL && *s) {
		/* Get the next and'd or or'd number */
		if ((next = strpbrk(s, "|&")) != NULL)
			*next++ = '\0';

		/* Determine if field is non-zero */
		if (*s == '+') {
			minval = 1;
			s = next;
			continue;
		}

		/* Determine value quantifier */
		if ((quantifier = strpbrk(s, "<>")) != NULL)
			s++;

		/* If this value is actually a range of values */
		//TODO: Maybe we should look harder when we find a range. But it seems
		//	like for all instances in the db file, a range means random ISN
		if( (secondValue = strpbrk(s, "-")) != NULL )
		{
			*secondValue++ = '\0';
			pers->TCP_ISN_gcd_min = strtol(s, &endptr, 16);
			pers->TCP_ISN_gcd_max = strtol(secondValue, &endptr, 16);
			//Choose value to be halfway between min and max
			//TODO: Should this be chosen randomly between min and max?
			pers->TCP_ISN_gcd = ((pers->TCP_ISN_gcd_max - pers->TCP_ISN_gcd_min)/2) + pers->TCP_ISN_gcd_min;
			return;
		}

		val = strtol(s, &endptr, 16);

		s = next;

		if (quantifier != NULL) {
			if (*quantifier != '>')
				continue;

			/* val is minval if | and val < minval or & */
			if (val < minval || !orexp)
				minval = val + 1;
			continue;
		}

		if (!orexp) {
			/* &,  minval is val */
			minval = val;
		} else if (orexp && val < minval) {
			/* |, val is minval if val < minval */
			minval = val;
		}
	}

	if (minval == 0 || minval == UINT_MAX)
		minval = 1;

	pers->TCP_ISN_gcd_min = minval;
	pers->TCP_ISN_gcd_max = minval;
	//Choose value to be halfway between min and max
	//TODO: Should this be chosen randomly between min and max?
	pers->TCP_ISN_gcd = ((pers->TCP_ISN_gcd_max - pers->TCP_ISN_gcd_min)/2) + pers->TCP_ISN_gcd_min;
}

int
parse_seq(struct personality *pers, int off, char *line)
{
	char *p = line, *p2, *end;

	while (p != NULL && strlen(p)) {
		p2 = strsep(&p, "%");
		end = p2;

		if (strncasecmp(p2, "SP=", 3) == 0) {
			p2 += 3;
			if (p == NULL)
				p = p2 + strlen(p2);
			char *endPtr;
			pers->TCP_SP_min = strtol(p2, &endPtr, 16);
			/* Expect a - (dash) delimiter */
			if( *endPtr == '-' )
			{
				p2 = endPtr + 1;
				pers->TCP_SP_max = strtol(p2, &endPtr, 16);
				//Chose value to be halfway between min and max
				//TODO: Should this be chosen randomly between min and max?
				pers->TCP_SP = ((pers->TCP_SP_max - pers->TCP_SP_min)/2) + pers->TCP_SP_min;
				if( *endPtr != '\0' )
				{
					return -1;
				}
			}
			else
			{
				return -1;
			}
		}
		else if (strncasecmp(p2, "GCD=", 4) == 0) {
			p2 += 4;
			if (p == NULL)
				p = p2 + strlen(p2);
			parse_seq_gcd(p2, p, pers);
		}
		else if (strncasecmp(p2, "ISR=", 4) == 0) {
			p2 += 4;
			if (p == NULL)
				p = p2 + strlen(p2);
			char *endPtr;
			pers->TCP_ISR_min = strtol(p2, &endPtr, 16);
			/* Expect a - (dash) delimiter */
			if( *endPtr == '-' )
			{
				p2 = endPtr + 1;
				pers->TCP_ISR_max = strtol(p2, &endPtr, 16);
				//Chose value to be halfway between min and max
				//TODO: Should this be chosen randomly between min and max?
				pers->TCP_ISR = ((pers->TCP_ISR_max - pers->TCP_ISR_min)/2) + pers->TCP_ISR_min;
				if( *endPtr != '\0' )
				{
					return -1;
				}
			}
			else
			{
				return -1;
			}

		}
		/* Improve IPID sequencing capability */
		else if (strncasecmp(p2, "TI=", 3) == 0) {
			int done = 0;

			end += 3;
			while (!done) {
				done = 1;
				p2 = strsep(&end, "|");
				if (strcasecmp(p2, "I") == 0) {
					pers->IPID_type_TI = ID_SEQUENTIAL;
				} else if (strcasecmp(p2, "BI") == 0) {
					pers->IPID_type_TI = ID_SEQUENTIAL_BROKEN;
				} else if (strcasecmp(p2, "Z") == 0) {
					if (end != NULL) {
						done = 0;
						continue;
					}
					pers->IPID_type_TI = ID_ZERO;
				} else if (strcasecmp(p2, "RD") == 0) {
					pers->IPID_type_TI = ID_RANDOM; 
				} else if (strcasecmp(p2, "RI") == 0) {
					pers->IPID_type_TI = ID_RPI;
				}
				/* Assume p2 must be a hex value for constant IPID */
				else {
					char *temp;
					uint32_t IPID_constant = strtol(p2, &temp, 16);
					if ( (*temp == '\0') && (p2 != NULL) ) /* IE: Conversion was successful */
					{
						pers->IPID_type_TI = ID_CONSTANT;
						pers->IPID_constant_val_TI = IPID_constant;
					}
					else
					{
						return -1;
					}
				}
			}

		}
		else if (strncasecmp(p2, "CI=", 3) == 0) {
			int done = 0;

			end += 3;
			while (!done) {
				done = 1;
				p2 = strsep(&end, "|");
				if (strcasecmp(p2, "I") == 0) {
					pers->IPID_type_CI = ID_SEQUENTIAL;
				} else if (strcasecmp(p2, "BI") == 0) {
					pers->IPID_type_CI = ID_SEQUENTIAL_BROKEN;
				} else if (strcasecmp(p2, "Z") == 0) {
					if (end != NULL) {
						done = 0;
						continue;
					}
					pers->IPID_type_CI = ID_ZERO;
				} else if (strcasecmp(p2, "RD") == 0) {
					pers->IPID_type_CI = ID_RANDOM;
				} else if (strcasecmp(p2, "RI") == 0) {
					pers->IPID_type_CI = ID_RPI;
				}
				/* Assume p2 must be a hex value for constant IPID */
				else {
					char *temp;
					uint32_t IPID_constant = strtol(p2, &temp, 16);
					if ( (*temp == '\0') && (p2 != NULL) ) /* IE: Conversion was successful */
					{
						pers->IPID_type_CI = ID_CONSTANT;
						pers->IPID_constant_val_CI = IPID_constant;
					}
					else
					{
						return -1;
					}
				}
			}
		}
		else if (strncasecmp(p2, "II=", 3) == 0) {
			int done = 0;

			end += 3;
			while (!done) {
				done = 1;
				p2 = strsep(&end, "|");
				if (strcasecmp(p2, "I") == 0) {
					pers->IPID_type_II = ID_SEQUENTIAL;
				} else if (strcasecmp(p2, "BI") == 0) {
					pers->IPID_type_II = ID_SEQUENTIAL_BROKEN;
				} else if (strcasecmp(p2, "Z") == 0) {
					if (end != NULL) {
						done = 0;
						continue;
					}
					pers->IPID_type_II = ID_ZERO;
				} else if (strcasecmp(p2, "RD") == 0) {
					pers->IPID_type_II = ID_RANDOM;
				} else if (strcasecmp(p2, "RI") == 0) {
					pers->IPID_type_II = ID_RPI;
				}
				/* Assume p2 must be a hex value for constant IPID */
				else {
					char *temp;
					uint32_t IPID_constant = strtol(p2, &temp, 16);
					if ( (*temp == '\0') && (p2 != NULL) ) /* IE: Conversion was successful */
					{
						pers->IPID_type_II = ID_CONSTANT;
						pers->IPID_constant_val_II = IPID_constant;
					}
					else
					{
						return -1;
					}
				}
			}
		}
		else if (strncasecmp(p2, "TS=", 3) == 0) {
			/* TCP timestamp sequencing capability */
			p2 = strsep(&end, "|");
			p2 += 3;

			//TODO: Handle the other values after the OR symbol. Choose one at random.
		  
			/* Hit some of the most common ones manually first */
			if (strcasecmp(p2, "1") == 0)
				pers->tstamphz = 2;
			else if (strcasecmp(p2, "7") == 0)
				pers->tstamphz = 100;
			else if (strcasecmp(p2, "8") == 0)
				pers->tstamphz = 200;
			else if (strcasecmp(p2, "0") == 0)
				pers->tstamphz = 0;
			else if (strcasecmp(p2, "A") == 0)
				pers->tstamphz = 1000;
			else if (strcasecmp(p2, "U") == 0)
				pers->tstamphz = -1;
			else
			{
				/* Try to convert to int */
				char *endpt;
				int exponent = strtol(p2, &endpt, 16);
				/* If conversion worked without fail */
				if( *endpt == '\0')
				{
					pers->tstamphz = pow(2, exponent);
					//TODO: Watch for integer overflow here
				}
				else
				{
					return (-1);
				}
			}
 		}
		else if (strncasecmp(p2, "SS=", 3) == 0) {
			p2 = strsep(&end, "|");
			p2 += 3;

			if (strcasecmp(p2, "S") == 0)
				pers->ipid_shared_sequence = 1;
			else if (strcasecmp(p2, "O") == 0)
				pers->ipid_shared_sequence = 0;
			else
			{
				return -1;
			}
		}
	}

	if (pers->TCP_ISN_gcd_min == 0)
		pers->TCP_ISN_gcd_min = 1;


	return (0);
}

int
parse_tl(struct personality *pers, int off, char *line)
{
	struct personate *test = &pers->t_tests[off];
	char *p = line, *p2, *end;

	if (strncasecmp(line, "R=N", 3) == 0) {
		test->flags = 0;
		return (0);
	}


	/* Permits Y|N, too */
	if (strncasecmp(line, "R=Y", 3) == 0) {
		p = strchr(p, '%');
		if (p == NULL)
			return (-1);
		p++;
	}
		
	while (p != NULL && strlen(p)) {
		p2 = strsep(&p, "%");
		/* We ignore all other values, only take the first */
		end = p2;
		p2 = strsep(&end, "|");

		if (strcasecmp(p2, "DF=Y") == 0) {
			test->df = 1;
		} else if (strcasecmp(p2, "DF=N") == 0) {
			test->df = 0;
		} else if (strncasecmp(p2, "W=", 2) == 0) {
			int smaller = 0;
			p2 += 2;

			/* Special cases */
			if (strcasecmp(p2, "O") == 0)
				continue;
			if (*p2 == '<') {
				p2++;
				smaller = 1;
			}

			test->window = strtoul(p2, &end, 16);
			if (end == NULL || *end != '\0')
				return (-1);

			if (smaller)
				test->window--;
		} else if (strncasecmp(p2, "ACK=", 4) == 0) {
			p2 += 4;
			/* Try to use S++ if that is an option */
			do {
				if (strcasecmp(p2, "O") == 0)
					test->forceack = ACK_ZERO;
				else if (strcasecmp(p2, "S") == 0)
					test->forceack = ACK_DECREMENT;
				else if (strcasecmp(p2, "S++") == 0)
					test->forceack = ACK_KEEP;
				else
					return (-1);
			} while (test->forceack != ACK_KEEP &&
			    (p2 = strsep(&end, "|")) != NULL);
		} else if (strncasecmp(p2, "Flags=", 6) == 0) {
			p2 += 6;

			/* Special case. A|AS should result in AS */
			if (end != NULL && *end != '\0')
				p2 = strsep(&end, "|");
			
			test->flags = 0;
			for (; *p2; p2++) {
				*p2 = tolower(*p2);
				switch (*p2) {
				case 'a':
					test->flags |= TH_ACK;
					break;
				case 's':
					test->flags |= TH_SYN;
					break;
				case 'f':
					test->flags |= TH_FIN;
					break;
				case 'r':
					test->flags |= TH_RST;
					break;
				case 'p':
					test->flags |= TH_PUSH;
					break;
				case 'u':
					test->flags |= TH_URG;
					break;
				case 'b':
					test->flags |= TH_ECE;
					break;
				default:
					return (-1);
				}
			}
		} else if (strncasecmp(p2, "O=", 2) == 0) {
			char *p3;
			p2 += 4;
			if (strlen(p2)) {
				for (p3 = p2; *p3; p3++)
					*p3 = tolower(*p3);
				if ((test->options = strdup(p2)) == NULL)
					err(1, "%s: strdup", __FUNCTION__);
			}
		} else
		      return (-1);
	}
	
	return (0);
}

#define RVAL_TRANS(x, p) do { \
	if (strcasecmp(p, "0") == 0) \
		(x) = RVAL_ZERO; \
	else if (strcasecmp(p, "E") == 0) \
		(x) = RVAL_OKAY; \
	else if (strcasecmp(p, "F") == 0) \
		(x) = RVAL_BAD; \
	else if (*p == '\0') \
		(x) = RVAL_OKAY;	/* Fill in default */ \
	else \
		return (-1); \
} while (0)

int
parse_u1(struct personality *pers, int off, char *line)
{
	struct persudp *test = &pers->udptest;
	char *p = line, *p2, *end;

	if (strncasecmp(line, "Resp=N", 6) == 0) {
		test->response = 0;
		return (0);
	}
	test->response = 1;

	if (strncasecmp(line, "Resp=Y%", 7) == 0)
		p += 7;
		
	while (p != NULL && strlen(p)) {
		p2 = strsep(&p, "%");
		/* We ignore all other values, only take the first */
		end = p2;
		p2 = strsep(&end, "|");

		if (strcasecmp(p2, "DF=Y") == 0) {
			test->df = 1;
		} else if (strcasecmp(p2, "DF=N") == 0) {
			test->df = 0;
		} else if (strcasecmp(p2, "DF=") == 0) {
			/* Fill in default */
			test->df = 0;
		} else if (strncasecmp(p2, "ULEN=", 5) == 0) {
			continue;
		} else if (strncasecmp(p2, "TOS=", 4) == 0) {
			p2 += 4;

			test->tos = strtoul(p2, &end, 16);
			if (end == NULL || *end != '\0')
				return (-1);
		} else if (strncasecmp(p2, "IPLEN=", 6) == 0) {
			p2 += 6;

			test->quotelen = strtoul(p2, &end, 16);
			if (end == NULL || *end != '\0')
				return (-1);
			test->quotelen -= IP_HDR_LEN + ICMP_HDR_LEN + 4;
		} else if (strncasecmp(p2, "RIPTL=", 6) == 0) {
			p2 += 6;

			test->riplen = strtoul(p2, &end, 16) - 328;
			if (end == NULL || *end != '\0')
				return (-1);
		} else if (strncasecmp(p2, "RID=", 4) == 0) {
			p2 += 4;
			RVAL_TRANS(test->rid, p2);
		} else if (strncasecmp(p2, "RIPCK=", 6) == 0) {
			p2 += 6;
			RVAL_TRANS(test->ripck, p2);
		} else if (strncasecmp(p2, "UCK=", 4) == 0) {
			p2 += 4;
			RVAL_TRANS(test->uck, p2);
		} else if (strncasecmp(p2, "DAT=", 4) == 0) {
			p2 += 4;
			RVAL_TRANS(test->dat, p2);
		} else
			return (-1);
	}
	
	return (0);
}

int
parse_ops(struct personality *pers, int off, char *line)
{
	char *p = line, *p2 = line, *end;

	while (p != NULL && strlen(p))
	{
		p2 = strsep(&p, "%");
		/* We ignore all other values, only take the first */
		end = p2;
		p2 = strsep(&end, "|");

		if (strncasecmp(p2, "O", 1) == 0)
		{
			p2++;
			uint testNumber = strtoul(p2, &end, 10);
			if( (testNumber >= 1) && (testNumber <= 6) )
			{
				testNumber--;
			}
			else
			{
				return -1;
			}

			//The number should have been just one digit
			if( end != p2+1 )
			{
				return -1;
			}
			p2 += 2;
			//Some OPS lines start with an OR for some reason... just ignore it.
			//	IS it trying to say that sometimes the options aren't present?
			if( *p2 == '|')
			{
				p2++;
			}

			//Allocate memory for the Options array
			uint numOptions = CountCharsInString(p2, "LNSMWT");
			uint dataSize = sizeof(struct tcp_option) * numOptions;
			pers->seq_tests[testNumber].options = (struct tcp_option *)malloc(dataSize);

			uint i = 0;
			while( *p2 != '\0')
			{
				pers->seq_tests[testNumber].options[i].opt_type = *p2;
				switch (*p2)
				{
					case 'L':
					case 'N':
					case 'S':
					{
						p2++;
						break;
					}
					case 'M':
					case 'W':
					{
						p2++;
						pers->seq_tests[testNumber].options[i].value = strtoul(p2, &end, 16);
						p2 = end;
						break;
					}
					case 'T':
					{
						pers->seq_tests[testNumber].options[i].TSval = *(p2+1);
						pers->seq_tests[testNumber].options[i].TSecr = *(p2+2);
						p2 += 3;
						break;
					}
					default:
					{
						//Error
						return -1;
					}
				}
				i++;
			}
		}
	}

	return 0;
}

//Helper function.
//Counts the number instances of the characters in *chars in the string *string
uint
CountCharsInString(char *string, char *chars)
{
	uint charsLength = strlen(chars);
	uint count = 0;
	uint i = 0;
	uint num = 0;
	while(*(string + i) != '\0')
	{
		uint j=0;
		for(; j < charsLength; j++)
		{
			num++;
			if( string[i] == chars[j] )
			{
				count++;
			}
		}
		i++;
	}

	return count;
}

int
parse_win(struct personality *pers, int off, char *line)
{

}

int
parse_ecn(struct personality *pers, int off, char *line)
{

}

int
parse_ie(struct personality *pers, int off, char *line)
{

}


struct parse_test {
	char *start;
	int offset;
	int (*parse_test)(struct personality *, int, char *);
} parse_tests[] = {
	{"SEQ", 0, parse_seq},
	{"OPS", 0, parse_ops},
	{"WIN", 0, parse_win},
	{"ECN", 0, parse_ecn},
	{"T1", 0, parse_tl},
	{"T2", 1, parse_tl},
	{"T3", 2, parse_tl},
	{"T4", 3, parse_tl},
	{"T5", 4, parse_tl},
	{"T6", 5, parse_tl},
	{"T7", 6, parse_tl},
	{"U1", 0, parse_u1},
	{"IE", 0, parse_ie},
	{NULL, 0, NULL}
};

int
personality_line(struct personality *pers, char *line)
{
	struct parse_test *pt = parse_tests;
	char *p, *p2;

	/* Ignore additional nmap output */
	if (strncasecmp(line, "Class", 5) == 0)
		return (0);

	p2 = line;
	p = strsep(&p2, "(");
	if (p2 == NULL)
		return (-1);
	p = strsep(&p2, ")");
	if (p2 == NULL)
		return (-1);
	for (; pt->start; pt++) {
		if (strncasecmp(line, pt->start, strlen(pt->start)) == 0)
			return (pt->parse_test(pers, pt->offset, p));
	}

	return (-1);
}

/* Creates a new personality and details on how to deal with duplicates */

struct personality *
personality_config_new(const char *name, int lineno)
{
	struct personality *pers;

	if ((pers = personality_new(name)) != NULL)
		return (pers);

	DFPRINTF(2, (stderr, "%d: Overwriting old fingerprint \"%s\"\n",
		lineno, name));

	/* Find the old personality, and remove it */
	pers = personality_find(name);
	personality_free(pers);

	return (personality_new(name));
}

/* Parsing Functions */

int
personality_parse(FILE *fin)
{
	char bl[1024], line[1024], *p, *p2;
	int errors = 0, lineno = 0, ignore = 0;
	struct personality *pers = NULL;

	while ((p = fgets(line, sizeof(line), fin)) != NULL) {
		strlcpy(bl, line, sizeof(bl));

		lineno++;
		p += strspn(p, WHITESPACE);

		if (*p == '\0' || *p == '#') {
			pers = NULL;
			continue;
		}

		/* Remove trailing comments */
		p2 = p;
		strsep(&p2, "#\r\n");

		if (CMP(p, FINGERPRINT) == 0) {
			p += sizeof(FINGERPRINT) - 1;
			p += strspn(p, ": \t");
			if (!isalnum(*p)) {
				fprintf(stderr, "%d: bad name \"%s\"\n",
				    lineno, p);
				return (-1);
			}
			for (p2 = p + strlen(p) - 1; isblank(*p2); p2--)
				*p2 = '\0';

			if ((pers = personality_config_new(p, lineno)) == NULL)
				ignore = 1;
			else
				ignore = 0;
			continue;
		}

		if (pers == NULL) {
			if (ignore)
				continue;

			fprintf(stderr, "%d: No personality for \"%s\"\n",
			    lineno, p);
			return (-1);
		}

		if (personality_line(pers, p) == -1) {
			fprintf(stderr, "%d: parse error: %s", lineno, bl);
			errors++;
		}
	}

	return (errors ? -1 : 0);
}

//-------------------------------------------------------------------
/* ET - Moved student xprobe parse functions from xprobe_parse.c */
/* CK - These are pretty much self-explanitory. Some are not very good.*/
/* ET - Actually none are very good since they don't return an error if
 *      an unexpected value was found.  In all cases, they look for
 *      all but one of the possible values, and if none of those values
 *      are found, the one value not searched for is returned.  Uggghhhh!
 *      This implementation should change.  At least there should be some
 *      enums or macros for the values instead of magic numbers.  */

static int
get_zero_notzero(char *input)
{                               /* returns 1 if zero, 0 otherwise */
	return (strncmp (input, "!0", 2) == 0);
}

/* ET - Added this one since the df bit is 0 or 1 */
static int
get_zero_one(char *input)
{                               /* returns 1 if zero, 0 otherwise */
	return (input[0] == '1');
}

static int
get_yes_no(char *input)
{                               /*returns 0 if y, 0 otherwise */
	return ((strncasecmp (input, "Y", 1) == 0));
}

static int
get_zero_ok_bad(char *input)
{
	if (input[0] == '0')
		return (1);
	else if (strncmp (input, "OK", 2) == 0)
		return (2);
	else if (strncmp (input, "BAD", 3) == 0)
		return (4);

	return (0);
}

static int
get_ok_flipped(char *input)
{
	if (strncmp (input, "OK", 2) == 0)
		return (1);
	else if (strncmp (input, "FLIPPED", 7) == 0)
		return (2);

	return 0;
}

static int
get_echoed_total_len(char *input)
{
	if (strcmp (input, ">20") == 0)
		return (1);
	else if (strcmp (input, "OK") == 0)
		return (2);
	else if (strcmp (input, "<20") == 0)
		return (4);

	return 0;
}

static int
get_echoed_dtsize (char *input)
{
	if (input[0] == '8')
		return (1);
	else if (strncmp (input, "64", 2) == 0)
		return (2);
	else if (strncmp (input, ">64", 3) == 0)
		return (4);

	return (0);
}

static struct ttl_pair
parse_and_load_ttl_pair(char *p)
{
	/* CK- Parse TTL pairs*/
	struct ttl_pair to_load;
	char *tmp_p = p;

	to_load.gt_lt = 0;
	if (p[0] == '>') {
		to_load.gt_lt = 1;
		strsep (&tmp_p, ">");
	} else if (p[0] == '<') {
		to_load.gt_lt = 2;
		strsep (&tmp_p, "<");
	}
	to_load.ttl_val = atoi (tmp_p);

	return (to_load);
}

/* ET - Called by get_fprint() only */
static int
set_xp_struct(struct xp_fingerprint *pers, char *line)
{
	/* CK- Parse xprobe lines. */
	char *p, *p2;
	int osname_len;
	int foo;

	p = p2 = line;
	if ((foo = strncasecmp (p2, "OS_ID", 5)) == 0) {
		/* Copy OS Name into structure:
		 * Gets the OS name into p2, assuming line has
		 * 'OS_ID = "OS"'
		 */
		strsep (&p2, "=");
		strsep (&p2, " ");
		strsep (&p2, "\"");
		p = strsep (&p2, "\"");
		if (p == NULL || p2 == NULL)
			return (0);
		osname_len = strcspn (p, "\0");
		if (osname_len <= 0)
			return (0);
		pers->os_id = strdup(p);
	} else {
		/* Copy other icmp values into structure:
		 * Assumes the the format is: 'icmp_... = val'
		 */
		if (strsep (&p2, "=") == NULL || p2 == NULL)
			return (0);
		p2 += strspn(p2, WHITESPACE);

		if (strncmp (p, "icmp_echo_code", 14) == 0) {
			pers->flags.icmp_echo_code = get_zero_notzero (p2);
		} else if (strncmp (p, "icmp_echo_ip_id", 15) == 0) {
			pers->flags.icmp_echo_ip_id = get_zero_notzero (p2);
		} else if (strncmp (p, "icmp_echo_tos_bits", 18) == 0) {
			pers->flags.icmp_echo_tos_bits = get_zero_notzero (p2);
		} else if (strncmp (p, "icmp_echo_df_bit", 16) == 0) {
			pers->flags.icmp_echo_df_bit = get_zero_one (p2);
		} else if (strncmp (p, "icmp_echo_reply_ttl", 19) == 0) {
			pers->ttl_vals.icmp_echo_reply_ttl = parse_and_load_ttl_pair (p2);
		} else if (strncmp (p, "icmp_timestamp_reply_ttl", 24) == 0) {
			pers->ttl_vals.icmp_timestamp_reply_ttl =
			    parse_and_load_ttl_pair (p2);
		} else if (strncmp (p, "icmp_timestamp_reply", 20) == 0) {
			pers->flags.icmp_timestamp_reply = get_yes_no (p2);
		} else if (strncmp (p, "icmp_addrmask_reply_ttl", 23) == 0) {
			pers->ttl_vals.icmp_addrmask_reply_ttl =
			    parse_and_load_ttl_pair (p2);
		} else if (strncmp (p, "icmp_addrmask_reply", 19) == 0) {
			pers->flags.icmp_addrmask_reply = get_yes_no (p2);
		} else if (strncmp (p, "icmp_info_reply_ttl", 19) == 0) {
			pers->ttl_vals.icmp_info_reply_ttl = parse_and_load_ttl_pair (p2);
		} else if (strncmp (p, "icmp_info_reply", 15) == 0) {
			pers->flags.icmp_info_reply = get_yes_no (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_dtsize", 26) == 0){
			pers->flags.icmp_unreach_echoed_dtsize = get_echoed_dtsize (p2);
		} else if (strncmp (p, "icmp_unreach_reply_ttl", 22) == 0) {
			pers->ttl_vals.icmp_unreach_reply_ttl =
			    parse_and_load_ttl_pair (p2);
		} else if (strncmp (p, "icmp_unreach_precedence_bits", 28) == 0) {
			pers->flags.icmp_unreach_precedence_bits = strtol (p2, NULL, 16);
		} else if (strncmp (p, "icmp_unreach_df_bit", 19) == 0) {
			pers->flags.icmp_unreach_df_bit = get_zero_one (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_udp_cksum", 29) == 0) {
			pers->flags.icmp_unreach_echoed_udp_cksum = get_zero_ok_bad (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_ip_cksum", 28) == 0) {
			pers->flags.icmp_unreach_echoed_ip_cksum = get_zero_ok_bad (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_ip_id", 25) == 0) {
			pers->flags.icmp_unreach_echoed_ip_id = get_ok_flipped (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_total_len", 29) == 0) {
			pers->flags.icmp_unreach_echoed_total_len =
			    get_echoed_total_len (p2);
		} else if (strncmp (p, "icmp_unreach_echoed_3bit_flags", 30) == 0) {
			pers->flags.icmp_unreach_echoed_3bit_flags = get_ok_flipped (p2);
		} else {
			/* Hmmm, got an unrecognized line.  You FAIL */
			return (0);
		}
	}

	return (1);
}

/* ET - Called by xprobe_personality_parse() only to parse a single FP */
/* CK - Parses one finger print at a time, returns a pointer */
static struct xp_fingerprint *
get_fprint(FILE * fp_in)
{
	char line[1024], *p, *p2;
	struct xp_fingerprint *pers = NULL;
	int generic = 0;

	pers = (struct xp_fingerprint *) calloc (1,sizeof (struct xp_fingerprint));
	if (pers == NULL) {
		warn("%s: Could not allocate\n", __func__);
		return (NULL);
	}

	/* Get a single line */
	while ((p = fgets (line, sizeof (line), fp_in)) != NULL) {
		/* Skip leading whitespace */
		p += strspn (p, WHITESPACE);
		/* Eliminate blank lines and comments */
		if (*p == '\0' || *p == '#')
			continue;

		/* Remove trailing comments */
		p2 = p;
		strsep (&p2, "#\r\n");

		/* Remove trailing whitespace  */
		for (p2 -= 2; (p2 >= p) && isspace (*p2); p2--)
			*p2 = '\0';

		/* Ignore the "fingperint {" line */
		if (CMP (p, XPRINT) == 0)
			continue;

		/* xprobe2.conf has a generic section.
		 * This skips that section */
		if (CMP (p, "generic") == 0)
			generic = 1;
		if (*p == '}') {
			if (!generic) {
				/* This closing brace signifies the end of
				 * a fingerprint. */
				return pers;
			}

			/* Unskip the generic section */
			generic = 0;
			continue;
		}

		/* Skip the generic section */
		if (generic)
			continue;
		/* This line is not a comment, blank line, or start of a fingerprint.
		 * So it must be a icmp_* or OS_ID line, right? :) */
		if (!set_xp_struct (pers, p)) {
			fprintf (stderr, "Errors setting struct\n");
			free(pers);
			return (NULL);
		}
	}

	/* If we return here, then we didn't get a complete fingerprint.
	 * Therefore we must free the alloced fingerprint and return NULL. */
	free(pers);

	return (NULL);
}

/* !!!DEBUG FUNCTION!!! */

static void
print_xprobe_struct(struct xp_fingerprint *pers)
{
	printf ("OS_ID:                             %s\n", pers->os_id);
	printf ("-- Module A --\n");
	printf ("icmp_echo_code:                    %d\n",
            pers->flags.icmp_echo_code);
	printf ("icmp_echo_ip_id:                   %d\n",
            pers->flags.icmp_echo_ip_id);
	printf ("icmp_echo_tos_bits:                %d\n",
            pers->flags.icmp_echo_tos_bits);
	printf ("icmp_echo_df_bit:                  %d\n",
            pers->flags.icmp_echo_df_bit);
	printf ("icmp_reply_ttl.gt_lt:              %d\n",
            pers->ttl_vals.icmp_echo_reply_ttl.gt_lt);
	printf ("icmp_reply_ttl.ttl_vals:           %d\n",
            pers->ttl_vals.icmp_echo_reply_ttl.ttl_val);
	printf ("-- Module B --\n");
	printf ("icmp_timestamp_reply:              %d\n",
            pers->flags.icmp_timestamp_reply);
	printf ("icmp_timestamp_reply_ttl.gt_lt:    %d\n",
            pers->ttl_vals.icmp_timestamp_reply_ttl.gt_lt);
	printf ("icmp_timestamp_reply_ttl.ttl_vals: %d\n",
            pers->ttl_vals.icmp_timestamp_reply_ttl.ttl_val);
	printf ("-- Module C --\n");
	printf ("icmp_addrmask_reply:               %d\n",
            pers->flags.icmp_addrmask_reply);
	printf ("icmp_addrmask_reply_ttl.gt_lt:     %d\n",
            pers->ttl_vals.icmp_addrmask_reply_ttl.gt_lt);
	printf ("icmp_addrmask_reply_ttl.ttl_vals:  %d\n",
            pers->ttl_vals.icmp_addrmask_reply_ttl.ttl_val);
	printf ("-- Module D --\n");
	printf ("icmp_info_reply:                   %d\n",
            pers->flags.icmp_info_reply);
	printf ("icmp_info_reply_ttl.gt_lt:         %d\n",
            pers->ttl_vals.icmp_info_reply_ttl.gt_lt);
	printf ("icmp_info_reply_ttl.ttl_vals:      %d\n",
            pers->ttl_vals.icmp_info_reply_ttl.ttl_val);
	printf ("-- Module E --\n");
	printf ("icmp_unreach_echoed_dtsize:        %d\n",
            pers->flags.icmp_unreach_echoed_dtsize);
	printf ("icmp_u_reply_ttl.gt_lt:            %d\n",
            pers->ttl_vals.icmp_unreach_reply_ttl.gt_lt);
	printf ("icmp_u_reply_ttl.ttl_vals:         %d\n",
            pers->ttl_vals.icmp_unreach_reply_ttl.ttl_val);
	printf ("icmp_unreach_precedence_bits:      0x%x\n",
            pers->flags.icmp_unreach_precedence_bits);
	printf ("icmp_unreach_df_bit:               %d\n",
            pers->flags.icmp_unreach_df_bit);
	printf ("icmp_unreach_echoed_udp_cksum:     %d\n",
            pers->flags.icmp_unreach_echoed_udp_cksum);
	printf ("icmp_unreach_echoed_ip_cksum:      %d\n",
            pers->flags.icmp_unreach_echoed_ip_cksum);
	printf ("icmp_unreach_echoed_ip_id:         %d\n",
            pers->flags.icmp_unreach_echoed_ip_id);
	printf ("icmp_unreach_echoed_total_len:     %d\n",
            pers->flags.icmp_unreach_echoed_total_len);
	printf ("icmp_unreach_echoed_3bit_flags:    %d\n",
            pers->flags.icmp_unreach_echoed_3bit_flags);
}

void
print_perstree(void)
{
	struct personality * pers;
	int i = 0;
	SPLAY_FOREACH(pers, perstree, &personalities) {
		if (pers->xp_fprint != NULL)
			printf("\tXP %d: %s\n", ++i, pers->xp_fprint->os_id);
	}
}

/**
 * Loads the xprobe fingerprint file and stores the fingerprints in the
 * correct personality based upon the association table
 *
 * @param fp The pre-fopen'd file to load
 * @return -1 on failure, 0 on success
 */

int
xprobe_personality_parse(FILE *fp)
{
	struct xp_fingerprint *new_print = NULL;

	if (fp == NULL) {
		fprintf (stderr, "Could not parse fingerprint file!");
		return (-1);
	}

	while (!feof (fp)) {
		/* Get a single fingerprint */
		new_print = get_fprint (fp); 
		if (new_print != NULL) {
			/* print_xprobe_struct (new_print); */
			SPLAY_INSERT(xp_fprint_tree, &xp_fprints, new_print);
			new_print = NULL;
		}
	}

	return (0);
}
