/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _OSFP_H_
#define _OSFP_H_

#include "pfvar.h"

#define OSFP_HASHSIZE	256		/* Needs to be power of 2 */
#define OSFP_TIMEOUT	(5 * 60)

struct osfp {
	SPLAY_ENTRY(osfp) node;
	struct event timeout;

	ip_addr_t	src;

	struct pf_osfp_enlist *list;
};

int honeyd_osfp_init(const char *);
int honeyd_osfp_match(const struct ip_hdr *, pf_osfp_t);
char *honeyd_osfp_name(struct ip_hdr *);

#endif
