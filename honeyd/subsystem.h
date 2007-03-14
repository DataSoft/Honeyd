/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _SUBSYSTEM_H_
#define _SUBSYSTEM_H_

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage {
        u_char iamasuckyoperatingsystem[256];
};
#endif

/* Templates can belong to multiple subsystems */
struct template_container {
	TAILQ_ENTRY(template_container) next;
	SPLAY_ENTRY(template_container) node;

	struct template *tmpl;
};

/* Subsystem state */

struct subsystem {
	TAILQ_ENTRY(subsystem) next;

	/* back pointers: IPv4 name */
	SPLAY_HEAD(subtmpltree, template_container) root;
	/* all templates */
	TAILQ_HEAD(templateq, template_container) templates;
	char *cmdstring;

	struct command cmd;

	int flags;
#define SUBSYSTEM_SHARED	0x01
#define SUBSYSTEM_RESTART	0x02

	struct timeval tv_restart;		/* time last started */

	TAILQ_HEAD(portqueue, port) ports;	/* list of configured ports */
};

#define SUBSYSTEM_RESTART_INTERVAL	5	/* time between restarts */

int templ_container_compare(struct template_container *,
    struct template_container *);
SPLAY_PROTOTYPE(subtmpltree, template_container, node,
    templ_container_compare);

#define SUBSYSTEM_MAGICFD	"SUBSYSTEM_MAGICFD"

enum subcmd { 
	SUB_BIND=1, SUB_LISTEN, SUB_CLOSE, SUB_CONNECT, SUB_SENDTO
};

struct subsystem_command {
	int domain;
	int type;
	int protocol;
	enum subcmd command;

	/* Local address */
	socklen_t len;
	struct sockaddr_storage sockaddr;

	/* Remote address */
	socklen_t rlen;
	struct sockaddr_storage rsockaddr;
};

void subsystem_insert_template(struct subsystem *, struct template *);
void subsystem_print(struct evbuffer *buffer, struct subsystem *sub);

#endif
