/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _GRE_
#define _GRE_

struct gre_hdr {
	uint16_t gre_flags;
	uint16_t gre_proto;
	uint16_t gre_sum;		/* Optional (RFC 2784) */
	uint16_t gre_reserved;		/* Optional (RFC 2784) */
} __attribute__((__packed__));

#define GRE_CHECKSUM	0x8000		/* Use the checksum field */
#define GRE_VERSION	0
#define GRE_IP4PROTO	0x800		/* Required by RFC */

#define GRE_NOCKSUM_DATA(x)	(u_char *)(&(x)->gre_sum)

int gre_encapsulate(ip_t *, struct addr *, struct addr *,
    struct ip_hdr *, u_int);
int gre_decapsulate(struct ip_hdr *, u_short oiplen, struct ip_hdr **, 
    u_short *);

#endif /* _GRE_ */
