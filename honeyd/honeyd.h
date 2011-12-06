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
#ifndef _HONEYD_H_
#define _HONEYD_H_

#define PIDFILE			"/var/run/honeyd.pid"

#define TCP_DEFAULT_SIZE	512
#define TCP_MAX_SIZE		4096
#define TCP_MAX_SEND		512

#define HONEYD_MTU		1500
#define HONEYD_MAX_INTERFACES	8

#define HONEYD_MAX_CONNECTS	32000

#define HONEYD_CLOSE_WAIT	60
#define HONEYD_SYN_WAIT		60
#define HONEYD_IDLE_TIMEOUT	300
#define HONEYD_DFL_TTL		64
#define HONEYD_UDP_WAIT		60
#define HONEYD_MAX_SOFTERRS	3	   /* Softerrors to state free*/

#define HONEYD_POLL_INTERVAL	{0, 10000}

#define HONEYD_ADDR_MASK        0xFFFFFF00 /* for ICMP address mask replies */

struct config {
	char *config;	 /* Name of configuration file */
	char *pers;
	char *xprobe;
	char *assoc;
	char *osfp;
};

struct count;
struct stats_network {
	struct count *input_bytes;
	struct count *output_bytes;
};

struct spoof {
	struct addr new_src;	/* where the reply should appear to come from */
	struct addr new_dst;	/* where the reply should go */
};

extern struct spoof no_spoof;

struct delay {
	struct event timeout;

	struct addr src;
	struct addr dst;

	struct template *tmpl;
	struct ip_hdr *ip;
	u_int iplen;

	struct spoof spoof;
	int flags;
};

#define DELAY_NEEDFREE	0x0001
#define DELAY_EXTERNAL	0x0002
#define DELAY_FREEPKT	0x0004
#define DELAY_TUNNEL	0x0008
#define DELAY_UNREACH	0x0010
#define DELAY_ETHERNET	0x0020	/* packet needs to be sent via ethernet */

enum status {PORT_OPEN = 0, PORT_PROXY, PORT_BLOCK, PORT_RESET,
	     PORT_SUBSYSTEM, PORT_PYTHON, PORT_RESERVED
};

enum forward {FW_DROP = 0, FW_INTERNAL, FW_EXTERNAL};

#define PORT_ISOPEN(x) ((x)->status == PORT_OPEN || \
			(x)->status == PORT_PROXY || \
			(x)->status == PORT_SUBSYSTEM || \
			(x)->status == PORT_PYTHON)			

struct interface;
struct subsystem;
struct action {
	char *action;
	void *action_extend;
	struct addrinfo *aitop;
	enum status status;
	int flags;
};

#define PORT_TARPIT	0x01

struct port_encapsulate;

struct port {
	SPLAY_ENTRY(port) node;
	TAILQ_ENTRY(port) next;

	TAILQ_HEAD(pendingq, port_encapsulate) pending;

	int proto;
	u_short number;

	struct action action;

	/* Subsystem related information */
	struct subsystem *sub;
	struct template *subtmpl;
	int sub_fd;
	int sub_islisten;
	struct port **sub_conport;
};

SPLAY_HEAD(porttree, port);

/* Contains information common to both UDP and TCP connections */

struct tuple {
	SPLAY_ENTRY(tuple) node;
	TAILQ_ENTRY(tuple) next;

	ip_addr_t ip_src;
	ip_addr_t ip_dst;
	uint16_t sport;
	uint16_t dport;

	int type;	/* Eiter SOCK_STREAM or SOCK_DGRAM */

	/* Statistics */
	uint32_t received;
	uint32_t sent;

	struct event timeout;

	int local;	/* locally initiated */

	/* Potentially pending connection to subsystem */
	struct port_encapsulate *pending;
};

SPLAY_HEAD(tree, tuple);
TAILQ_HEAD(conlru, tuple);

struct command {
	pid_t pid;
	int pfd;
	int perrfd;

	struct event pread;
	struct event pwrite;
	struct event peread;

	uint8_t fdconnected:1,
	        fdwantclose:1,
		fdgotfin:1,	/* if data still buffered delay shutdown */
	        unused:5;

	void *state;		/* Currently used only for Python */
};

/*
 * For subsystems, we need to be able to schedule a callback that hands
 * the subsytem a file descriptor to the new connection.  However, Honeyd
 * may not block on this as this might lead to dead lock with the
 * subsystem.  Intead, we encapsulate all the necessary information and
 * hope that the underlying data does not go away.  XXX: that's a bug.
 */

struct port_encapsulate {
	TAILQ_ENTRY(port_encapsulate) next;

	struct tuple *hdr;
	struct command *cmd;
	struct port *port;
	void *con;

	struct event ev;
};

/* State about TCP connections */

struct tcp_con {
	/* Has to be the first member of the structure */
	struct tuple conhdr;
#define con_ipsrc conhdr.ip_src
#define con_ipdst conhdr.ip_dst
#define con_sport conhdr.sport
#define con_dport conhdr.dport

	uint8_t dupacks;
	uint32_t snd_una;

	uint32_t rcv_next;
	uint32_t last_acked;

	struct template *tmpl;
	uint8_t rcv_flags;

	struct command cmd;
#define cmd_pfd	cmd.pfd
#define cmd_perrfd cmd.perrfd

	u_char *payload;
	u_int psize;
	u_int plen;		/* date in buffer */
	u_int poff;		/* current send offset */

	u_char *readbuf;
	u_int rsize;
	u_int rlen;

	uint8_t state;
	uint8_t sentfin:1,
		finacked:1,
		sawwscale:1,
		sawtimestamp:1,
		unused:4;

	u_short	mss;
	u_short window;

	uint32_t echotimestamp;

	u_short retrans_time;

	struct event retrans_timeout;

	struct port *port;		/* used if bound to sub system */

	uint16_t flags;			/* Currently used for tarpitting */

	uint8_t recv_mss;
	uint8_t recv_window;
};

#define TCP_TARPIT	0x01

#define MAX_UDP_BUFFERS	10

struct conbuffer {
	TAILQ_ENTRY(conbuffer) next;

	u_char *buf;
	size_t len;
};

struct udp_con {
	/* Has to be the first member of the structure */
	struct tuple conhdr;

	struct template *tmpl;

	struct command cmd;

	TAILQ_HEAD(bufferq, conbuffer) incoming;
	int nincoming;

	int softerrors;		/* ICMP unreachables for this state */

	struct port *port;
};

struct callback {
	void (*cb_read)(int, short, void *);
	void (*cb_write)(int, short, void *);
	void (*cb_eread)(int, short, void *);
	void (*cb_connect)(int, short, void *);
};

/* YM
 * Timestamp message data
 */
struct icmp_msg_timestamp { /* dnet.h define this but the size is wrong */
				/* So define ours */
	struct icmp_hdr hdr;			/* ICMP header */
	uint16_t        icmp_id;                /* identifier */
        uint16_t        icmp_seq;               /* sequence number */
        uint32_t        icmp_ts_orig;           /* originate timestamp */
        uint32_t        icmp_ts_rx;             /* receive timestamp */
        uint32_t        icmp_ts_tx;             /* transmit timestamp */
};

/* YM
 * Address mask message data, RFC 950
 */
struct icmp_mesg_mask { /* Our definition */
	struct icmp_hdr hdr;			/* ICMP header */
        uint16_t        icmp_id;                /* identifier */
        uint16_t        icmp_seq;               /* sequence number */
        uint32_t        icmp_mask;              /* address mask */
};

/* YM
 * Information Reply message data, RFC 792
 */
struct icmp_msg_inforeply { /* Our definition */
	struct icmp_hdr hdr;			/* ICMP header */
	struct icmp_msg_idseq idseq;		/* ID_SEQ */
};

#define TCP_BYTESINFLIGHT(x)	(x)->poff
#define TCP_MAX_INFLIGHT	4096

/* Iterate over all active connections */
int tuple_iterate(struct conlru *, int (*f)(struct tuple *, void *), void *);
struct tuple *tuple_find(struct tree *, struct tuple *);

void honeyd_ip_send(u_char *, u_int, struct spoof spoof);
void honeyd_dispatch(struct template *, struct ip_hdr *, u_short);
char *honeyd_contoa(const struct tuple *);

void honeyd_input(const struct interface *, struct ip_hdr *, u_short);

/* Command prototypes for services */
void cmd_droppriv(uid_t, gid_t);

void cmd_ready_fd(struct command *, struct callback *, void *);
void cmd_trigger_read(struct command *, int);
void cmd_trigger_write(struct command *, int);
void cmd_free(struct command *);
int cmd_fork(struct tuple *, struct command *, struct template *,
    char *, char **, void *);
int cmd_python(struct tuple *, struct command *, void *);
int cmd_subsystem(struct template *, struct subsystem *, char *, char **);

struct addrinfo;
struct addrinfo *cmd_proxy_getinfo(char *, int, short);
int cmd_proxy_connect(struct tuple *, struct command *, struct addrinfo *,
    void *);

int cmd_subsystem_schedule_connect(struct tuple *hdr, struct command *cmd,
    struct port *, void *arg);
int cmd_subsystem_connect(struct tuple *hdr, struct command *cmd,
    struct port *, void *arg);
int cmd_subsystem_localconnect(struct tuple *hdr, struct command *cmd,
    struct port *, void *arg);

/* Network connection elements */
struct tcp_con *tcp_new(struct ip_hdr *, struct tcp_hdr *, int);
struct udp_con *udp_new(struct ip_hdr *, struct udp_hdr *, int);
int tcp_setupconnect(struct tcp_con *);
void tcp_connectfail(struct tcp_con *con);

void generic_timeout(struct event *, int);

/* Network protocol related prototypes */
int conhdr_compare(struct tuple *, struct tuple *);

void tcp_free(struct tcp_con *);
int tcp_send(struct tcp_con *, uint8_t, u_char *, u_int);
void tcp_senddata(struct tcp_con *, uint8_t);
void tcp_sendfin(struct tcp_con *);

void udp_free(struct udp_con *);
int udp_send(struct udp_con *con, u_char *payload, u_int len);

void config_init(void);
void config_read(char *);

struct port *port_insert(struct template *, int, int, struct action *);
struct port *port_random(struct template *, int, struct action *, int, int);
struct port *port_find(struct template *, int, int);
void port_free(struct template *, struct port *);
void port_encapsulation_free(struct port_encapsulate *);

void icmp_echo_reply(struct template *, struct ip_hdr *, uint8_t,
    uint8_t, uint16_t, uint8_t,	u_char *, u_int, struct spoof spoof);
void change_quote_header(struct ip_hdr *, uint16_t, 
    uint16_t, uint16_t, uint16_t, uint16_t);
void icmp_unreachable_reply(struct ip_hdr *rip, uint8_t ttl, uint8_t tos,
	uint16_t df, uint16_t riplen, struct spoof spoof);
void icmp_mask_reply(struct template *, struct ip_hdr *, 
	struct icmp_msg_idseq *, uint8_t, uint32_t, struct spoof spoof);
void icmp_info_reply(struct template *, struct ip_hdr *, 
		struct icmp_msg_idseq *, uint8_t, struct spoof spoof);
void icmp_timestamp_reply(struct template *, struct ip_hdr *,
    struct icmp_msg_timestamp *, uint8_t, struct spoof spoof);

void honeyd_use_uid(uid_t);
void honeyd_use_gid(gid_t);

#endif
