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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#include <grp.h>
#include <getopt.h>
#include <dnet.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "osfp.h"
#include "hsniff.h"
#include "hooks.h"
#include "interface.h"
#include "tagging.h"
#include "stats.h"
#include "debug.h"

int			honeyd_debug;

static int		hsniff_show_version;
static int		hsniff_show_usage;
static int		hsniff_useudp;
static uid_t		hsniff_uid = 32767;
static gid_t		hsniff_gid = 32767;

static struct option hsniff_long_opts[] = {
	{"version",     0, &hsniff_show_version, 1},
	{"help",        0, &hsniff_show_usage, 1},
	{0, 0, 0, 0}
};

struct tree tcpcons;

SPLAY_PROTOTYPE(tree, tuple, node, conhdr_compare);
SPLAY_GENERATE(tree, tuple, node, conhdr_compare);

void
usage(void)
{
	fprintf(stderr,
		"Usage: hsniff [OPTIONS] [net ...]\n\n"
		"where options include:\n"
		"  -d                     Do not daemonize, be verbose.\n"
		"  -V, --version          Print program version and exit.\n"
		"  -h, --help             Print this message and exit.\n"
	    );
	
	exit(1);
}

void
hsniff_settcp(struct tcp_track *con, struct ip_hdr *ip, struct tcp_hdr *tcp,
    int local)
{
	struct tuple *hdr = &con->conhdr;

	memset(hdr, 0, sizeof(struct tuple));
	hdr->ip_src = ip->ip_src;
	hdr->ip_dst = ip->ip_dst;
	hdr->sport = ntohs(tcp->th_sport);
	hdr->dport = ntohs(tcp->th_dport);
	hdr->type = SOCK_STREAM;
	hdr->local = local;

	TAILQ_INIT(&con->segments);
}

void
hsniff_setudp(struct udp_con *con, struct ip_hdr *ip, struct udp_hdr *udp,
    int local)
{
	struct tuple *hdr = &con->conhdr;

	memset(hdr, 0, sizeof(struct tuple));
	hdr->ip_src = ip->ip_src;
	hdr->ip_dst = ip->ip_dst;
	hdr->sport = ntohs(udp->uh_sport);
	hdr->dport = ntohs(udp->uh_dport);
	hdr->type = SOCK_DGRAM;
	hdr->local = local;
	con->softerrors = 0;
	con->cmd.pfd = -1;
	con->cmd.perrfd = -1;

	TAILQ_INIT(&con->incoming);
}

static void
syslog_init(int argc, char *argv[])
{
	int options, i;
	char buf[MAXPATHLEN];

#ifdef LOG_PERROR
	options = LOG_PERROR|LOG_PID|LOG_CONS;
#else
	options = LOG_PID|LOG_CONS;
#endif
	openlog("hsniff", options, LOG_DAEMON);	

	/* Create a string containing all the command line
	 * arguments and pass it to syslog:
	 */

	buf[0] = '\0';
	for (i = 1; i < argc; i++) {
		if (i > 1 && strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
			break;
		if (strlcat(buf, argv[i], sizeof(buf)) >= sizeof(buf))
			break;
	}

	syslog(LOG_NOTICE, "started with %s", buf);
}

void
hsniff_init(void)
{
	/* Initalize ongoing connection state */
	SPLAY_INIT(&tcpcons);
}

void
hsniff_exit(int status)
{
	interface_close_all();

	closelog();

	exit(status);
}

void
generic_timeout(struct event *ev, int seconds)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = seconds;
	evtimer_add(ev, &tv);
}

struct tcp_track *
tcp_track_new(struct ip_hdr *ip, struct tcp_hdr *tcp, int local)
{
	struct tcp_track *con;

	if ((con = calloc(1, sizeof(struct tcp_track))) == NULL) {
		syslog(LOG_WARNING, "calloc: %m");
		return (NULL);
	}

	hsniff_settcp(con, ip, tcp, local);
	evtimer_set(&con->timeout, hsniff_tcp_timeout, con);

	SPLAY_INSERT(tree, &tcpcons, &con->conhdr);

	TAILQ_INIT(&con->segments);
	return (con);
}

void
tcp_track_free(struct tcp_track *con)
{
	struct tcp_segment *seg;
	SPLAY_REMOVE(tree, &tcpcons, &con->conhdr);

	while ((seg = TAILQ_FIRST(&con->segments)) != NULL) {
		TAILQ_REMOVE(&con->segments, seg, next);
		free(seg);
	}

	hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr,
	    NULL, 0);

	evtimer_del(&con->timeout);

	free(con);
}

void
hsniff_tcp_timeout(int fd, short event, void *arg)
{
	struct tcp_track *con = arg;

	syslog(LOG_DEBUG, "Expiring TCP %s (%p)",
	    honeyd_contoa(&con->conhdr), con);

	tcp_track_free(con);
}

void
tcp_insert(struct tcp_track *con, uint32_t th_seq, void *data, size_t dlen)
{
	struct tcp_segment *seg, *newseg;

	TAILQ_FOREACH(seg, &con->segments, next) {
		/* New packet before data that we have seen so far */
		if (TCP_SEQ_LEQ(th_seq + dlen, seg->seq)) {
			newseg = calloc(1, sizeof(struct tcp_segment));
			if (newseg == NULL)
			{
				syslog(LOG_ERR, "%s: calloc", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: calloc", __func__);
			TAILQ_INSERT_BEFORE(seg, newseg, next);
			return;
		}

		/* Packet is a total duplicate */
		if (TCP_SEQ_LEQ(th_seq + dlen, seg->seq + seg->len))
			return;

		/* There is some overlap */
		if (TCP_SEQ_LT(th_seq, seg->seq + seg->len)) {
			uint32_t off;

			off = seg->seq + seg->len - th_seq;
			th_seq += off;
			data += off;
			dlen -= off;
		}
	}
}

void
tcp_drop_subsumed(struct tcp_track *con)
{
	struct tcp_segment *seg;
	uint32_t off;

	while ((seg = TAILQ_FIRST(&con->segments)) != NULL) {
		/* This segment is still in the future */
		if (TCP_SEQ_GT(seg->seq, con->snd_una))
			break;

		/* For all other segments, we can do some work */
		TAILQ_REMOVE(&con->segments, seg, next);

		/* The old segment is completely covered, so we can drop it */
		if (TCP_SEQ_LEQ(seg->seq + seg->len, con->snd_una)) {
			free(seg);
			continue;
		}

		if (seg->seq != con->snd_una) {
			/* The data overlaps */
			off = con->snd_una - seg->seq;
			seg->seq += off;
			seg->len -= off;
		}

		/*
		 * We are matching up a previously stored segment,
		 * so we can stream its content out.
		 */

		syslog(LOG_NOTICE, "Streaming: %s %u: %d",
		    honeyd_contoa(&con->conhdr), con->snd_una, seg->len);
		hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM,
		    &con->conhdr, seg->data, seg->len);

		con->snd_una += seg->len;
		free(seg);
	}
}

void
tcp_recv_cb(u_char *pkt, u_short pktlen)
{
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	struct tcp_track *con, tmp;
	uint32_t th_seq;
	uint16_t th_sum;
	size_t dlen;
	u_char *data;
	uint8_t tiflags;

	ip = (struct ip_hdr *)pkt;
	tcp = (struct tcp_hdr *)(pkt + (ip->ip_hl << 2));
	data = (u_char *)(pkt + (ip->ip_hl*4) + (tcp->th_off*4));
	
	if (pktlen < (ip->ip_hl << 2) + TCP_HDR_LEN)
		return;

	/* Check the checksum the brutal way, until libdnet supports */
	th_sum = tcp->th_sum;
	ip_checksum(ip, pktlen);
	if (th_sum != tcp->th_sum)
		return;

	th_seq = ntohl(tcp->th_seq);

	tiflags = tcp->th_flags;
	hsniff_settcp(&tmp, ip, tcp, 0);
	con = (struct tcp_track *)SPLAY_FIND(tree, &tcpcons, &tmp.conhdr);
	if (con == NULL) {
		/* Only create new connections upon seeing a SYN packet */
		if (!(tiflags & TH_SYN) || (tiflags & (TH_ACK|TH_RST)))
			return;

		/* Need to create new tcp connection tracker */
		if ((con = tcp_track_new(ip, tcp, 0)) == NULL)
			return;

		con->snd_una = th_seq + 1;
	}

	/* 
	 * We need to hear back from this connection every so often,
	 * or we are going to time it out.
	 */
	generic_timeout(&con->timeout, HSNIFF_CON_EXPIRE);

	hooks_dispatch(ip->ip_p, HD_INCOMING, &tmp.conhdr, pkt, pktlen);
	
	dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (tcp->th_off << 2);

	/*
	 * This is responsible for ignoring the initial syn packet,
	 * so checking for SYN further below is safe.
	 */
	if (TCP_SEQ_LEQ(th_seq + dlen, con->snd_una))
		return;

	/* There is some overlap */
	if (TCP_SEQ_LT(th_seq, con->snd_una)) {
		uint32_t off;

		off = con->snd_una - th_seq;
		th_seq += off;
		data += off;
		dlen -= off;
	}

	if (th_seq == con->snd_una) {
		/* Inform our listener about the new data */
		syslog(LOG_NOTICE, "Streaming: %s %u: %d",
		    honeyd_contoa(&con->conhdr), con->snd_una, dlen);
		hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr,
		    data, dlen);
		con->snd_una = th_seq + dlen;
		
		tcp_drop_subsumed(con);
	} else {
		if (TCP_SEQ_GEQ(th_seq, con->snd_una + TCP_WIN_MAX) &&
		    TCP_SEQ_LEQ(th_seq, con->snd_una + TCP_WIN_MAX * 2)) {
			/*
			 * We probably lost some packets that are not going
			 * to be retransmitted.
			 */
			con->snd_una = th_seq - TCP_WIN_MAX;
			tcp_drop_subsumed(con);
		}

		/* Only insert data that is at most one window away */
		if (TCP_SEQ_LEQ(th_seq, con->snd_una + TCP_WIN_MAX))
			tcp_insert(con, th_seq, data, dlen);
	} 

	if (tiflags & (TH_RST|TH_FIN|TH_SYN)) {
		/* 
		 * Check if the conditions for closing this connection,
		 * have been met.
		 */
		if (TCP_SEQ_GEQ(th_seq, con->snd_una) &&
		    TCP_SEQ_LEQ(th_seq, con->snd_una + TCP_WIN_MAX)) {
			tcp_track_free(con);
			return;
		}
	}
}

void
udp_recv_cb(u_char *pkt, u_short pktlen)
{
	struct ip_hdr *ip = NULL;
	struct udp_hdr *udp;
	struct udp_con tmp;
	
	uint16_t uh_sum;
	u_char *data;
	u_int dlen;

	ip = (struct ip_hdr *)pkt;
	udp = (struct udp_hdr *)(pkt + (ip->ip_hl << 2));

	if (pktlen < (ip->ip_hl << 2) + UDP_HDR_LEN)
		return;

	hsniff_setudp(&tmp, ip, udp, 0);
	hooks_dispatch(ip->ip_p, HD_INCOMING, &tmp.conhdr, pkt, pktlen);

	data = (u_char *)(pkt + (ip->ip_hl*4) + UDP_HDR_LEN);
	dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - UDP_HDR_LEN;
	if (dlen != (ntohs(udp->uh_ulen) - UDP_HDR_LEN))
		return;
	
	uh_sum = udp->uh_sum;
	if (uh_sum) {
		ip_checksum(ip, pktlen);
		if (uh_sum != udp->uh_sum)
			return;
	}

	hooks_dispatch(ip->ip_p, HD_INCOMING_STREAM, &tmp.conhdr, data, dlen);
}

void
hsniff_recv_cb(u_char *ag, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	const struct interface *inter = (const struct interface *)ag;
	struct ip_hdr *ip;
	u_short iplen;

	/* Everything below assumes that the packet is IPv4 */
	if (pkthdr->caplen < inter->if_dloff + IP_HDR_LEN)
		return;

	ip = (struct ip_hdr *)(pkt + inter->if_dloff);

	iplen = ntohs(ip->ip_len);
	if (pkthdr->caplen - inter->if_dloff < iplen)
		return;
	if (ip->ip_hl << 2 > iplen)
		return;
	if (ip->ip_hl << 2 < sizeof(struct ip_hdr))
		return;

	switch(ip->ip_p) {
	case IP_PROTO_TCP:
		tcp_recv_cb((u_char *)ip, iplen);
		break;
	case IP_PROTO_UDP:
		if (hsniff_useudp)
			udp_recv_cb((u_char *)ip, iplen);
		break;
	default:
		return;
	}
}

void
hsniff_signal(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "exiting on signal %d", fd);
	hsniff_exit(0);
}

int
main(int argc, char *argv[])
{
	extern int interface_dopoll;
	struct event sigterm_ev, sigint_ev;
	char *dev[HSNIFF_MAX_INTERFACES];
	char **orig_argv;
	char *osfp = PATH_HONEYDDATA "/pf.os";
	struct addr stats_dst;
	u_short stats_port = 0;
	char *stats_username = NULL;
	char *stats_password = NULL;
	char filter[2048], line[128];
	int i, c, orig_argc, ninterfaces = 0;
	FILE *fp;

	orig_argc = argc;
	orig_argv = argv;
	while ((c = getopt_long(argc, argv, "VPUdc:i:u:g:f:0:h?",
				hsniff_long_opts, NULL)) != -1) {
		char *ep;
		switch (c) {
		case 'U':
			hsniff_useudp = 1;
			break;
		case 'c': {
			char line[1024], *p = line;
			char *address;
			char *strport;
			char *name;
			char *password;

			strlcpy(line, optarg, sizeof(line));

			if ((address = strsep(&p, ":")) == NULL)
				usage();
			if ((strport = strsep(&p, ":")) == NULL)
				usage();
			if ((name = strsep(&p, ":")) == NULL)
				usage();
			if ((password = strsep(&p, ":")) == NULL)
				usage();
			if (p != NULL && *p != '\0')
				usage();

			if (addr_pton(address, &stats_dst) == -1) {
				fprintf(stderr, "Bad destination address %s\n",
				    address);
				usage();
			}
			if ((stats_port = atoi(strport)) == 0) {
				fprintf(stderr, "Bad destination port %s\n",
				    strport);
				usage();
			}

			stats_username = strdup(name);
			stats_password = strdup(password);
		}
			break;
		case 'u':
			hsniff_uid = strtoul(optarg, &ep, 10);
			if (optarg[0] == '\0' || *ep != '\0') {
				fprintf(stderr, "Bad uid %s\n", optarg);
				usage();
			}
			break;
		case 'g':
			hsniff_gid = strtoul(optarg, &ep, 10);
			if (optarg[0] == '\0' || *ep != '\0') {
				fprintf(stderr, "Bad gid %s\n", optarg);
				usage();
			}
			break;
		case 'V':
			hsniff_show_version = 1;
			break;
		case 'P':
			interface_dopoll = 1;
			break;
		case 'd':
			honeyd_debug++;
			break;
		case 'i':
			if (ninterfaces >= HSNIFF_MAX_INTERFACES)
			{
				syslog(LOG_ERR, "Too many interfaces specified");
				exit(EXIT_FAILURE);
			}
				//errx(1, "Too many interfaces specified");
			dev[ninterfaces++] = optarg;
			break;
		case '0':
			osfp = optarg;
			break;
		case 0:
			/* long option handled -- skip this one. */
			break;
		default:
			usage();
			/* not reached */
		}
	}

	if (hsniff_show_version) {
		printf("Hsniff Version %s\n", VERSION);
		exit(0);
	}
	if (hsniff_show_usage) {
		usage();
		/* not reached */
	}

	argc -= optind;
	argv += optind;

	filter[0] = '\0';
	while (argc > 0) {
		struct addr addr;

		if (addr_pton(*argv, &addr) == -1)
		{
			syslog(LOG_ERR, "invalid address \"%s\"", *argv);
			exit(EXIT_FAILURE);
		}
			//errx(1, "invalid address \"%s\"", *argv);

		if (strlen(filter) &&
		    strlcat(filter, " or ", sizeof(filter)) >= sizeof(filter))
		{
			syslog(LOG_ERR, "too many addresses; filter too big");
			exit(EXIT_FAILURE);
		}
			//errx(1, "too many addresses; filter too long");

		if (addr.addr_bits == 32) {
			snprintf(line, sizeof(line), "(not src %s and dst %s)",
			    addr_ntoa(&addr), addr_ntoa(&addr));
			if (strlcat(filter, line, sizeof(filter)) >= 
			    sizeof(filter))
			{
				syslog(LOG_ERR, "too many addresses; filter too big");
				exit(EXIT_FAILURE);
			}
				//errx(1, "too many address; filter too long");
		} else {
			snprintf(line, sizeof(line),
			    "(not src net %s and dst net %s)",
			    addr_ntoa(&addr), addr_ntoa(&addr));
			if (strlcat(filter, line, sizeof(filter)) >= 
			    sizeof(filter))
			{
				syslog(LOG_ERR, "too many addresses, filter too big");
				exit(EXIT_FAILURE);
			}
				//errx(1, "too many address; filter too long");
		}
		argv++;
		argc--;
	}

	if (strlen(filter)) {
		extern char *interface_filter;

		interface_filter = filter;
	} else {
		fprintf(stderr, "no addresses specified\n");
		usage();
		/* NOTREACHED */
	}

	fprintf(stderr, "Hsniff V%s Copyright (c) 2004-2007 Niels Provos\n",
	    VERSION);

	/* disabled event methods that don't work with bpf */
	interface_prevent_init();

	event_init();

	syslog_init(orig_argc, orig_argv);

	/* Initialize Honeyd's callback hooks */
	hooks_init();

	interface_initialize(hsniff_recv_cb);

	if (stats_username == NULL)
	{
		syslog(LOG_ERR, "no username specified for stats reporting");
		exit(EXIT_FAILURE);
	}
		//errx(1, "no username specified for stats reporting");

	stats_init();
	stats_init_collect(&stats_dst, stats_port,
	    stats_username, stats_password);

	/* PF OS fingerprints */
	if (honeyd_osfp_init(osfp) == -1)
	{
		syslog(LOG_ERR, "failed to read OS fingerprints");
		exit(EXIT_FAILURE);
	}
		//errx(1, "reading OS fingerprints failed");

	/* Initialize the specified interfaces */
	if (ninterfaces == 0)
		interface_init(NULL, argc, argc ? argv : NULL);
	else {
		for (i = 0; i < ninterfaces; i++)
			interface_init(dev[i], argc, argc ? argv : NULL);
	}

	/* Create PID file, we might not be able to remove it */
	unlink(HSNIFF_PIDFILE);
	if ((fp = fopen(HSNIFF_PIDFILE, "w")) == NULL)
	{
		syslog(LOG_ERR, "fopen, failed to open file");
		exit(EXIT_FAILURE);
	}
		//err(1, "fopen");

	/* Start Hsniff in the background if necessary */
	if (!honeyd_debug) {
		setlogmask(LOG_UPTO(LOG_INFO));
		
		fprintf(stderr, "Hsniff starting as background process\n");
		if (daemon(1, 0) < 0) {
			unlink(HSNIFF_PIDFILE);
			syslog(LOG_ERR, "daemon");
			exit(EXIT_FAILURE);
			//err(1, "daemon");
		}
	}
	
	fprintf(fp, "%d\n", getpid());
	fclose(fp);
	
	chmod(HSNIFF_PIDFILE, 0644);

	/* Drop privileges if we do not need them */
	droppriv(hsniff_uid, hsniff_gid);

	syslog(LOG_NOTICE,
	    "Demoting process privileges to uid %u, gid %u",
	    hsniff_uid, hsniff_gid);

	signal_set(&sigint_ev, SIGINT, hsniff_signal, NULL);
	signal_add(&sigint_ev, NULL);
	signal_set(&sigterm_ev, SIGTERM, hsniff_signal, NULL);
	signal_add(&sigterm_ev, NULL);

	event_dispatch();

	syslog(LOG_ERR, "Kqueue does not recognize bpf filedescriptor.");

	return (0);
}

/* Drop the privileges and verify that they got dropped */

#define SETERROR(x) do { \
	snprintf x; \
	strlcat(error, errline, sizeof(error)); \
} while (0)

void
droppriv(uid_t uid, gid_t gid)
{
	static char error[1024];
	static char errline[256];

	error[0] = '\0';

	/* Lower privileges */
#ifdef HAVE_SETGROUPS
	if (setgroups(1, &gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setgroups(%d) failed\n", __func__, gid));
#endif
#ifdef HAVE_SETREGID
	if (setregid(gid, gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setregid(%d) failed\n", __func__, gid));
#endif
	if (setegid(gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setegid(%d) failed\n", __func__, gid));
	if (setgid(gid) == -1)
		SETERROR((errline, sizeof(errline), 
			     "%s: setgid(%d) failed\n", __func__, gid));
#ifdef HAVE_SETREUID
	if (setrugid(uid, uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setreuid(%d) failed\n", __func__, uid));
#endif
#ifdef __OpenBSD__
	if (seteuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: seteuid(%d) failed\n", __func__, gid));
#endif
	if (setuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setuid(%d) failed\n", __func__, gid));

	if (getgid() != gid || getegid() != gid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set gid to %d", __func__, gid));
		goto error;
	}

	if (getuid() != uid || geteuid() != uid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set uid to %d", __func__, uid));
		goto error;
	}

	/* Make really sure that we dropped them */
	if (uid != 0 && (setuid(0) != -1 || seteuid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}
	if (gid != 0 && (setgid(0) != -1 || setegid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}

	return;
 error:
	syslog(LOG_ERR, "%s: terminated", __func__);
	exit(EXIT_FAILURE);
	//errx(1, "%s: terminated", __func__);
}
