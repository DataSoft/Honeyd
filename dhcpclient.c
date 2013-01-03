/*
 * Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
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

/*
 * dhcpclient.c
 *
 * Copyright (c) 2004 Marius Aamodt Eriksen <marius@monkey.org>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: dhcpclient.c,v 1.6 2005/07/20 21:13:11 provos Exp $
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>

#include <stdlib.h>
#include <err.h>
#include <syslog.h>
#include <string.h>
#include <syslog.h>

#include <dnet.h>
#include <event.h>

#include "honeyd.h"
#include "interface.h"
#include "arp.h"
#include "template.h"
#include "dhcpclient.h"

extern char *templateDump;
extern rand_t *honeyd_rand;

int need_dhcp = 0;	/* set to one if a configuration specifies dhcp */

static struct timeval _timeout_tv = {1, 0};

#define NTRIES 10

static int  _pack_request(struct dhcpclient_req *, void *, size_t *);
static int  _pack_release(struct dhcpclient_req *, void *, size_t *);
static int  _bcast(struct template *,
                int (*)(struct dhcpclient_req *, void *, size_t *));
static int  _unicast(struct template *,
                int (*)(struct dhcpclient_req *, void *, size_t *));
static void _dhcp_timeout_cb(int, short, void *);
static void _dhcp_reply(struct template *, u_char *, size_t);
static struct template * _dhcp_dequeue();
int 		 _dhcp_getconf(struct template *);

//DHCP Queue type definitions
typedef struct node
{
	struct template* m_template;
	struct node* m_next;
} QueueNode;

typedef struct
{
	QueueNode* m_front;
	QueueNode* m_rear;
	unsigned int m_count;
} Queue;

static Queue *dhcp_queue = NULL;

void
queue_dhcp_discover(struct template *tmpl)
{
	//Initialize the queue if this is the first operation
	if(dhcp_queue == NULL)
	{
		dhcp_queue = (Queue*) malloc(sizeof(Queue));
		dhcp_queue->m_count = 0;
		dhcp_queue->m_front = NULL;
		dhcp_queue->m_rear = NULL;
	}

	QueueNode* nextQueueNode;

	if(!(nextQueueNode = (QueueNode*)malloc(sizeof(QueueNode))))
	{
		//TODO: malloc returned an error, let's at least make a warning
		return;
	}

	nextQueueNode->m_template = tmpl;
	nextQueueNode->m_next = NULL;

	if (dhcp_queue->m_count == 0)
	{
		dhcp_queue->m_front = nextQueueNode;
	}
	else
	{
		dhcp_queue->m_rear->m_next = nextQueueNode;
	}

	(dhcp_queue->m_count)++;
	dhcp_queue->m_rear = nextQueueNode;
}

struct template *_dhcp_dequeue()
{
	if(dhcp_queue == NULL)
	{
		return NULL;
	}
	if(dhcp_queue->m_count == 0)
	{
		return 0;
	}

	(dhcp_queue->m_count)--;
	QueueNode* front = dhcp_queue->m_front;
	dhcp_queue->m_front = front->m_next;

	struct template *template = front->m_template;
	free(front);
	return template;
}

void
dhcp_send_discover()
{
	//This will start the chain of discoveries. We only need to start it
	//	out with the front of the queue if this is the first run
	struct template *template = _dhcp_dequeue();
	if(template != NULL)
	{
		_dhcp_getconf(template);
	}
}

int
_dhcp_getconf(struct template *tmpl)
{
	struct dhcpclient_req *req = tmpl->dhcp_req;
	struct interface *inter = tmpl->inter;

	if (req == NULL) {
		req = calloc(1, sizeof(struct dhcpclient_req));
		if (req == NULL)
		{
			syslog(LOG_ERR, "%s: calloc");
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: calloc");
		tmpl->dhcp_req = req;
	}

	syslog(LOG_NOTICE, "[%s] trying DHCP", inter->if_ent.intf_name);

	if (req->state != 0) {
		warnx("Aborting DHCP configuration in progress");
		dhcp_abort(tmpl);
	}

	/* For now, do the pcap in here independently. */

	gettimeofday(&req->timer, NULL);

	assert(tmpl->ethernet_addr);

	req->state |= DHREQ_STATE_WAITANS | DHREQ_STATE_BUSY;
	req->xid = rand_uint32(honeyd_rand);
	req->ea = tmpl->ethernet_addr->addr_eth;

	if (_bcast(tmpl, _pack_request) < 0)
		return (-1);

	req->ntries = 0;

	evtimer_set(&req->timeoutev, _dhcp_timeout_cb, tmpl);
	evtimer_add(&req->timeoutev, &_timeout_tv);

	return (0);
}

int
dhcp_release(struct template *tmpl)
{
	struct dhcpclient_req *req = tmpl->dhcp_req;

	if (!(req->nc.defined & NC_HOSTADDR))
		return (-1);

	return (_unicast(tmpl, _pack_release));
}

void
dhcp_abort(struct template *tmpl)
{
	struct dhcpclient_req *req = tmpl->dhcp_req;

	if (req == NULL) {
		struct addr *eth_addr = tmpl->ethernet_addr;
		syslog(LOG_WARNING,
		    "%s: called without request on template %s",
		    __func__,
		    eth_addr != NULL ? addr_ntoa(eth_addr) : tmpl->name);
		return;
	}

	if (req->state == 0)
		return;

	event_del(&req->timeoutev);

	req->state = 0;
}

static void
_dhcp_timeout_cb(int fd, short ev, void *arg)
{
	struct template *tmpl = arg;
	struct interface* inter = tmpl->inter;
	struct dhcpclient_req *req = tmpl->dhcp_req;
	struct timeval timeout_tv;

	assert(inter != NULL);

	if (req->ntries++ > NTRIES) {
	  	printf("aborting dhclient on interface %s after %d tries\n", 
		    inter->if_ent.intf_name, req->ntries);
		dhcp_abort(tmpl);
		//Try the next template
		dhcp_send_discover();
		return;
	}

	_bcast(tmpl, _pack_request);

	if (req->ntries < 5)
		timeout_tv.tv_sec = 1;
	else
	  	/* backoff on sending dhcp requests */
		timeout_tv.tv_sec = 0x01 << (req->ntries - 4);

	/* set a limit on the backoff */
	if (timeout_tv.tv_sec > 128)
		timeout_tv.tv_sec = 128;

	timeout_tv.tv_usec = 0;
	evtimer_add(&req->timeoutev, &timeout_tv);
}

static void
netconf_mknetmask(struct addr *ipaddr, struct addr *ipmask)
{
	uint32_t mask;
	u_int bits = 32;

	mask = ntohl(ipmask->addr_ip);

	while (!(mask & 0x1) && bits > 0) {
		mask >>= 1;
		bits--;
	}

	ipaddr->addr_bits = bits;
}

static void
_dhcp_reply(struct template *tmpl, u_char *buf, size_t buflen)
{
	struct dhcpclient_req *req = tmpl->dhcp_req;
	struct dhcp_msg *msg = (struct dhcp_msg *)buf;
	size_t optlen = buflen - sizeof(*msg);
	uint8_t *p, *end, opt1, opt1len, *opt1p;
	short replyreq = 0, ack = 0, done = 0;
	struct netconf nc;
	struct addr *which = NULL, ipmask;

	if (req->xid != msg->dh_xid)
		return;

	memset(&nc, 0, sizeof(nc));
	memset(&ipmask, 0, sizeof(ipmask));

	/* Parse the options on the reply message */

	p = (u_char *)msg + sizeof(*msg);
	end = p + optlen;
	while (p < end) {
		opt1 = *p++;
		if (p == end)
			break;
		if (opt1 != 0x00 && done)
			goto optdone;
		switch (opt1) {
		case 0x00:
			continue;
		case 0xff:
			done = 1;
			continue;
		default:
			opt1len = *p++;
			if (p + opt1len >= end)
				goto optdone;

			opt1p = p;
			p += opt1len;

			break;
		}

		switch (opt1) {
		case DH_SUBNETMASK:
			nc.defined |= NC_MASK;
			which = &ipmask;
			break;
		case DH_ROUTER:
			nc.defined |= NC_GWADDR;
			which = &nc.gwaddr;
			break;
		case DH_NS:
			nc.defined |= NC_NSADDR;
			which = &nc.nsaddr[0];
			break;
		case DH_SERVIDENT:
			which = &req->servident;
			break;
		default:
			break;
		}

		switch(opt1) {
		case DH_MSGTYPE:
			if (req->state & DHREQ_STATE_WAITANS &&
			    *opt1p == DH_MSGTYPE_OFFER)
				replyreq = 1;
			if (req->state & DHREQ_STATE_WAITACK &&
			    *opt1p == DH_MSGTYPE_ACK)
				ack = 1;
			break;
		case DH_DOMAINNAME: {
			size_t len = MIN(sizeof(nc.domain) - 1, opt1len);
			memcpy(nc.domain, opt1p, len);
			nc.domain[len] = '\0';
			nc.defined |= NC_DOMAIN;
			break;
		}
		case DH_SERVIDENT:
		case DH_SUBNETMASK:
		case DH_NS:
		case DH_ROUTER: {
			uint32_t addr;

			if (opt1len < IP_ADDR_LEN)
				goto optdone;

			memcpy(&addr, opt1p, sizeof(addr));
			addr = /* ntohl( */addr/* ) */;
			addr_pack(which, ADDR_TYPE_IP, IP_ADDR_BITS,
			    &addr, sizeof(addr));
			break;
		}
		default:
			break;
		}
	}

 optdone:
	/*
	 * XXX - Does not warn if the error is on the last one..  make
	 * opterr instead.
	 */
	if (p < end)
		warnx("Error processing options");

	if (ack || replyreq) {
		uint32_t ipaddr;

		req->nc = nc;
		ipaddr = /* ntohl( */msg->dh_yiaddr/* ) */;
		addr_pack(&req->nc.hostaddr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ipaddr, sizeof(ipaddr));
		req->nc.defined |= NC_HOSTADDR;
	}

	if (replyreq) {
		req->state &= ~DHREQ_STATE_WAITANS;
		req->state |= DHREQ_STATE_WAITACK;

		_bcast(tmpl, _pack_request);
	}

	if (ack) {
		struct addr addr = req->nc.hostaddr;
		struct interface *inter = tmpl->inter;

		syslog(LOG_NOTICE, "[%s] got DHCP offer: %s",
		    inter->if_ent.intf_name, addr_ntoa(&addr));

		dhcp_abort(tmpl);
		//Abort resets the state variable, so we have to set it again afterward
		req->state = DHREQ_STATE_GOTACK;

		if (template_find(addr_ntoa(&addr)) != NULL) {
			syslog(LOG_WARNING,
			    "%s: Already got a template named %s",
			    __func__, addr_ntoa(&addr));
			return;
		}


		/* We are done - tell the template about our luck */
		template_remove(tmpl);
		free(tmpl->name);
		tmpl->name = strdup(addr_ntoa(&addr));
		if (tmpl->name == NULL)
		{
			syslog(LOG_ERR, "%s: strdup", __func__);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: strdup", __func__);
		template_insert(tmpl);
		template_dump_ips(templateDump);

		/* Update our ARP table */
		syslog(LOG_DEBUG, "Updating ARP binding: %s -> %s",
		    addr_ntoa(tmpl->ethernet_addr), tmpl->name);
		template_remove_arp(tmpl);

		template_post_arp(tmpl, &addr);

		/* Callback for central configuration here. */
		if (ipmask.addr_type != 0)
			netconf_mknetmask(&req->nc.hostaddr, &ipmask);
		else
			req->nc.hostaddr.addr_bits = 24;

		//If we got an ack, then go ahead and send another discover
		dhcp_send_discover();
	}
}

/*
 * Receives a UDP packet from port 68 to port 67 from the Honeyd packet
 * dispatcher and attempts to find the correct template for it.
 */

void
dhcp_recv_cb(struct eth_hdr *eth, struct ip_hdr *ip, u_short iplen)
{
	struct arp_req *arp;
	struct template *tmpl;
	struct dhcpclient_req *req = NULL;
	struct udp_hdr *udp;
	size_t msglen;
	struct dhcp_msg *msg;
	uint16_t ip_sum, uh_sum;
	struct addr eth_dha;

	/* IPv4 only */

	/* Check if we manage a virtual machine with this ethernet address */
	addr_pack(&eth_dha, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    &eth->eth_dst, ETH_ADDR_LEN);

	udp = (struct udp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
	msg = (struct dhcp_msg *)((u_char *)udp + UDP_HDR_LEN);
	msglen = ntohs(udp->uh_ulen) - UDP_HDR_LEN;

	memcpy(&eth_dha.__addr_u.__data8[0], (&msg->dh_chaddr[0]), ETH_ADDR_LEN);

	arp = arp_find(&eth_dha);
	if ( (arp == NULL) || !(arp->flags & ARP_INTERNAL))
		return;

	tmpl = arp->owner;
	req = tmpl->dhcp_req;
	if (req == NULL) {
		syslog(LOG_WARNING, "%s: received DHCP reply for template %s "
		    "without dhcp_req", __func__, addr_ntoa(&eth_dha));
		return;
	}

	if (!(req->state & (DHREQ_STATE_WAITANS | DHREQ_STATE_WAITACK)))
		return;

	if (msglen != (iplen - (ip->ip_hl << 2) - UDP_HDR_LEN))
		return;

	ip_sum = ip->ip_sum;
	uh_sum = udp->uh_sum;
	ip_checksum(ip, iplen);
	if (ip_sum != ip->ip_sum || uh_sum != udp->uh_sum) {
		syslog(LOG_WARNING, "%s: bad checksum for template %s",
		    __func__, addr_ntoa(&eth_dha));
		return;
	}

	/* save the servers address */
	memcpy(&req->server_ea, &eth->eth_src, ETH_ADDR_LEN);

	_dhcp_reply(tmpl, (u_char *)msg, msglen);
}

static int
_bcast(struct template *tmpl,
    int (*_pack)(struct dhcpclient_req *, void *, size_t *))
{
	struct eth_hdr *eth;
	uint8_t buf[1024], *p;
	size_t restlen = 1024, len, iplen;
	struct udp_hdr *udph;
	struct ip_hdr *iph;
	struct dhcpclient_req *req = tmpl->dhcp_req;
	struct interface *inter = tmpl->inter;

	assert(req != NULL);
	assert(inter != NULL);

	memset(buf, 0, sizeof(buf));

	p = &buf[0];
	eth = (struct eth_hdr *)p;
	eth_pack_hdr(eth, ETH_ADDR_BROADCAST, req->ea, ETH_TYPE_IP);

	restlen -= ETH_HDR_LEN;
	p += ETH_HDR_LEN;

	iph = (struct ip_hdr *)p;
	ip_pack_hdr(iph, 0, 0, 0, 0, 16,
	    IP_PROTO_UDP, IP_ADDR_ANY, IP_ADDR_BROADCAST);

	p += IP_HDR_LEN;
	restlen -= IP_HDR_LEN;

	udph = (struct udp_hdr *)p;
	udp_pack_hdr(udph, 68, 67, 0);

	p += UDP_HDR_LEN;
	restlen -= UDP_HDR_LEN;

	(*_pack)(req, p, &restlen);

	len = 1024 - restlen;
	iplen = len - ETH_HDR_LEN;

	iph->ip_len = htons(iplen);
	udph->uh_ulen = htons(iplen - IP_HDR_LEN);

	ip_checksum(buf + ETH_HDR_LEN, iplen);

	if (eth_send(inter->if_eth, buf, len) < 0)
	{
		syslog(LOG_ERR, "eth_send function call failed");
		exit(EXIT_FAILURE);
	}
	//err(1, "eth_send");

	return (0);
}

static int
_unicast(struct template *tmpl,
    int (*_pack)(struct dhcpclient_req *, void *, size_t *))
{
	struct eth_hdr *eth;
	uint8_t buf[1024], *p;
	size_t restlen = 1024, len, iplen;
	struct udp_hdr *udph;
	struct ip_hdr *iph;
	struct dhcpclient_req *req = tmpl->dhcp_req;
	struct interface *inter = tmpl->inter;

	assert(req != NULL);
	assert(inter != NULL);

	memset(buf, 0, sizeof(buf));

	p = &buf[0];
	eth = (struct eth_hdr *)p;
	eth_pack_hdr(eth, req->server_ea, req->ea, ETH_TYPE_IP);

	restlen -= ETH_HDR_LEN;
	p += ETH_HDR_LEN;

	iph = (struct ip_hdr *)p;
	ip_pack_hdr(iph, 0, 0, 0, 0, 16,
	    IP_PROTO_UDP,
	    req->nc.hostaddr.addr_ip, req->nc.gwaddr.addr_ip);

	p += IP_HDR_LEN;
	restlen -= IP_HDR_LEN;

	udph = (struct udp_hdr *)p;
	udp_pack_hdr(udph, 68, 67, 0);

	p += UDP_HDR_LEN;
	restlen -= UDP_HDR_LEN;

	(*_pack)(req, p, &restlen);

	len = 1024 - restlen;
	iplen = len - ETH_HDR_LEN;

	iph->ip_len = htons(iplen);
	udph->uh_ulen = htons(iplen - IP_HDR_LEN);

	ip_checksum(buf + ETH_HDR_LEN, iplen);

	if (eth_send(inter->if_eth, buf, len) < 0)
	{
		syslog(LOG_ERR, "eth_send function call failed");
		exit(EXIT_FAILURE);
	}
		//err(1, "eth_send");

	return (0);
}

/*
 * We should cache dhcp packets.
 */
static int
_pack_request(struct dhcpclient_req *req, void *buf, size_t *restlen)
{
	struct dhcp_msg *msg;
	u_char *p;
	size_t optlen, padlen = 0;
	struct timeval tv, difftv;
	struct netconf *nc = &req->nc;

	gettimeofday(&tv, NULL);
	timersub(&tv, &req->timer, &difftv);

	//3 bytes for Message type
	//7 bytes for Requested Parameters
	//1 byte for End of Options
	optlen = (3) + (7) + (1);

	optlen += 6 * (nc->defined & NC_HOSTADDR) + 
	    6 * (req->servident.addr_type != 0);
/* 	optlen += (nc->defined & NC_DOMAIN) * strlen(nc->domain); */

	if (*restlen < sizeof(*msg) + optlen)
		return (-1);

	msg = (struct dhcp_msg *)buf;

	msg->dh_op = DH_BOOTREQUEST;
	msg->dh_htype = DH_HTYPE_ETHERNET;
	msg->dh_hlen = ETH_ADDR_LEN;
	msg->dh_xid = req->xid;
	msg->dh_secs = htons((uint16_t)difftv.tv_sec);

	memcpy(msg->dh_chaddr, &req->ea, ETH_ADDR_LEN);

	msg->dh_magiccookie = htonl(DH_MAGICCOOKIE);

	p = (u_char *)buf + sizeof(*msg);

	/* Options */

	/* Message type */
	*p++ = DH_MSGTYPE;
	*p++ = 1;
	*p++ = req->state & DHREQ_STATE_WAITANS ?
	    DH_MSGTYPE_DISCOVER : DH_MSGTYPE_REQUEST;

	/* Requested Parameters */
	*p++ = DH_PARAMREQ;
	*p++ = 4;		/* Number of parameters */
	*p++ = 1;		/* Subnet mask */
	padlen += 4;
	*p++ = 28;		/* Broadcast address */
	padlen += 4;	
	*p++ = 3;		/* Router */
	padlen += 4;	
	*p++ = 6;		/* Domain name server */
	padlen += 4;
/* 	*p++ = 12;		/\* Host name *\/ */

	if (nc->defined & NC_HOSTADDR) {
		uint32_t ipaddr;
		*p++ = DH_REQIP;
		*p++ = 4;
		ipaddr = /* htonl( */nc->hostaddr.addr_ip/* ) */;
		memcpy(p, &ipaddr, IP_ADDR_LEN);
		p += IP_ADDR_LEN;
	}

	if (req->servident.addr_type != 0) {
		uint32_t ipaddr;
		*p++ = DH_SERVIDENT;
		*p++ = 4;
		ipaddr = /* htonl( */req->servident.addr_ip/* ) */;
		memcpy(p, &ipaddr, IP_ADDR_LEN);
		p += IP_ADDR_LEN;
	}

	*p = 0xff;		/* End options */

	*restlen -= sizeof(*msg) + optlen;

	if (*restlen >= padlen)
		*restlen -= padlen;	/* Fix for retarted DHCP servers. */

	return (0);
}

static int
_pack_release(struct dhcpclient_req *req, void *buf, size_t *restlen)
{
	struct dhcp_msg *msg;
	u_char *p;
	size_t optlen, padlen = 0;
	struct netconf *nc = &req->nc;

	optlen = (3) + (1); /* just message type */

	if (*restlen < sizeof(*msg) + optlen)
		return (-1);

	msg = (struct dhcp_msg *)buf;

	memset(msg, 0, sizeof(struct dhcp_msg));
	msg->dh_op = DH_BOOTREQUEST;
	msg->dh_htype = DH_HTYPE_ETHERNET;
	msg->dh_hlen = ETH_ADDR_LEN;
	msg->dh_xid = req->xid;

	memcpy(msg->dh_chaddr, &req->ea, ETH_ADDR_LEN);
	msg->dh_ciaddr = nc->hostaddr.addr_ip;

	msg->dh_magiccookie = htonl(DH_MAGICCOOKIE);

	p = (u_char *)buf + sizeof(*msg);

	/* Options */

	/* Message type */
	*p++ = DH_MSGTYPE;
	*p++ = 1;
	*p++ = DH_MSGTYPE_RELEASE;

	*p = 0xff;		/* End options */

	*restlen -= sizeof(*msg) + optlen;

	if (*restlen >= padlen)
		*restlen -= padlen;	/* Fix for retarted DHCP servers. */

	return (0);
}
