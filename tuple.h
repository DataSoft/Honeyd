/*
 * tuple.h
 */

#ifndef TUPLE_H_
#define TUPLE_H_


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

/* Contains information common to both UDP and TCP connections */
struct tuple {
	SPLAY_ENTRY(tuple) node;
	TAILQ_ENTRY(tuple) next;

	struct addr address_src;
	struct addr address_dst;

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



#endif /* TUPLE_H_ */
