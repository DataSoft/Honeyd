/*
 * Copyright (c) 2003-2005 Niels Provos <provos@citi.umich.edu>
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

#ifndef _TEMPLATE_
#define _TEMPLATE_

#include <assert.h>

struct dhcpclient_req;
struct personality;
struct subsystem;
struct ip_hdr;
struct condition;

struct subsystem_container {
	TAILQ_ENTRY(subsystem_container) next;

	struct subsystem *sub;
};

TAILQ_HEAD(subsystemqueue, subsystem);

struct template {
	SPLAY_ENTRY(template) node;

	char *name;

	struct porttree ports;

	struct action icmp;
	struct action tcp;
	struct action udp;

	struct personality *person;

	uint16_t ipid;
	uint16_t IPID_last_TCP;
	uint16_t IPID_last_ICMP;

	uint32_t seq;
	int seqcalls;

	uint32_t timestamp;
	struct timeval tv;			/* drifted time */
	struct timeval tv_real;		/* real wall time */

	struct timeval tv_ISN;		//Used for calculating the ISN timing
	float drift;

	uint16_t drop_inrate;
	uint16_t drop_synrate;

	uid_t uid;
	gid_t gid;

	/* Maximum number of file descriptors for spawned process */
	int max_nofiles;

	TAILQ_HEAD(subsyscontainerqueue, subsystem_container) subsystems;

	/* Condition on which this template is activated */
	TAILQ_HEAD(conditionqueue, condition) dynamic;
	int dynamic_rulenr;
	
	/* Special handling for templates */
	int flags;
	struct interface *inter;

	/* Set when we are to use this ethernet_address */
	struct addr *ethernet_addr;

	/* Set if we want to assign an IP address via DHCP */
	struct dhcpclient_req *dhcp_req;

	/* optional spoof source and destination for the reply */
	struct spoof spoof;

	/* Reference counter */
	uint16_t refcnt;
};

#define TEMPLATE_EXTERNAL	0x0001	/* Real machine on external network */
#define TEMPLATE_DYNAMIC	0x0002	/* Pointer to templates */
#define TEMPLATE_DYNAMIC_CHILD	0x0004  /* Is dynamic child */

/* Required to access template from different source files */
SPLAY_HEAD(templtree, template);
int		templ_compare(struct template *, struct template *);
SPLAY_PROTOTYPE(templtree, template, node, templ_compare);

struct template	*template_create(const char *);
int		template_add(struct template *, int, int, struct action *);
int		template_subsystem(struct template *, char *, int);
void		template_subsystem_start(struct template *tmpl,
		    struct subsystem *sub);
struct template	*template_clone(const char *, const struct template *,
		    struct interface *, int);
struct template *template_find(const char *);
struct template *template_find_best(const char *, const struct ip_hdr *,
		    u_short);
void		template_list_glob(struct evbuffer *buffer,
		    const char *pattern);

void		template_post_arp(struct template *, struct addr *);
void		template_remove_arp(struct template *);

int		template_insert_dynamic(struct template *, struct template *,
		    struct condition *);

#define TEMPLATE_FREE_REGULAR		0x00
#define TEMPLATE_FREE_DEALLOCATE	0x01
void		template_free_all(int how);
void		template_subsystem_free(struct subsystem *);
void		template_subsystem_free_ports(struct subsystem *);
void		template_subsystem_list_glob(struct evbuffer *buffer,
		    const char *pattern);

int		templ_compare(struct template *, struct template *);

/* Get a temporary IP address to be used with DHCP */
int		template_get_dhcp_address(struct addr *addr);

void		template_remove(struct template *);
int		template_insert(struct template *);
void		template_deallocate(struct template *);

void		template_print(struct evbuffer*, struct template *);

/* Iterate across all templates and call the callback function for each */
int		template_iterate(int (*f)(struct template *, void *),
		    void *arg);

#define template_free(x)	do {					\
	if ((x) == NULL)						\
		break;							\
	/* Decrease ref counter */					\
	(x)->refcnt--;							\
	if ((x)->refcnt <= 0)						\
		template_deallocate(x);					\
} while (0)

static __inline struct template *
template_ref(struct template *tmpl)
{
	if (tmpl != NULL) {
		tmpl->refcnt++;
		assert(tmpl->refcnt);
	}
	return (tmpl);
}

void template_test(void);

#endif /* _TEMPLATE_ */
