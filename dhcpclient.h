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
 */

#ifndef _DHCPCLIENT_H
#define _DHCPCLIENT_H

#define NC_HOSTADDR   0x01
#define NC_GWADDR     0x02
#define NC_MASK       0x04
#define NC_DOMAIN     0x08
#define NC_NSADDR     0x10

struct netconf {
	struct addr hostaddr;
	struct addr gwaddr;
	char        domain[256];
	struct addr nsaddr[4];
	short       defined;
};

#define DHREQ_STATE_BUSY         0x01
#define DHREQ_STATE_WAITANS      0x02
#define DHREQ_STATE_WAITACK      0x04

struct dhcpclient_req {
	int             state;
	eth_addr_t      ea;		/* our own */
	eth_addr_t	server_ea;	/* from the server */
	uint32_t        xid;
	struct event    timeoutev;
	struct timeval  timer;
	struct netconf  nc;
	struct addr     servident;
	int             ntries;
};

#define DH_BOOTREQUEST 1
#define DH_BOOTREPLY   2

#define DH_MAGICCOOKIE 0x63825363

#define DH_MSGTYPE_DISCOVER 1
#define DH_MSGTYPE_OFFER    2
#define DH_MSGTYPE_REQUEST  3
#define DH_MSGTYPE_DECLINE  4
#define DH_MSGTYPE_ACK      5
#define DH_MSGTYPE_NAK      6
#define DH_MSGTYPE_RELEASE  7

#define DH_SUBNETMASK  1
#define DH_ROUTER      3
#define DH_NS          6
#define DH_HOSTNAME    12
#define DH_DOMAINNAME  15
#define DH_REQIP       50
#define DH_MSGTYPE     53
#define DH_SERVIDENT   54
#define DH_PARAMREQ    55

#define DH_HTYPE_ETHERNET 1

struct dhcp_msg {
	uint8_t	 dh_op;
	uint8_t  dh_htype;
	uint8_t  dh_hlen;
	uint8_t  dh_hops;
	uint32_t dh_xid;
	uint16_t dh_secs;
	uint16_t dh_flags;
	uint32_t dh_ciaddr;
	uint32_t dh_yiaddr;
	uint32_t dh_siaddr;
	uint32_t dh_giaddr;
	uint8_t  dh_chaddr[16];
	char     dh_sname[64];
	char     dh_file[128];
	uint32_t dh_magiccookie;
	/* And options are packed onto here.. */
} __attribute__((__packed__));

struct template;
int  dhcp_getconf(struct template *);
void dhcp_abort(struct template *);
int dhcp_release(struct template *);

void dhcp_recv_cb(struct eth_hdr *, struct ip_hdr *, u_short);

#endif /* _DHCPCLIENT_H */
