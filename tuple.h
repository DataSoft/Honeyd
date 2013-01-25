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

	struct event *ev;
};

/* Contains information common to both UDP and TCP connections */
struct tuple {
	struct {
		struct tuple *spe_left; /* left element */
		struct tuple *spe_right; /* right element */
	} node;
	TAILQ_ENTRY(tuple) next;

	// IP layer src/dst packet come from
	struct addr address_src;
	struct addr address_dst;

	// Link layer src/dst packet came from
	struct addr linkLayer_src;
	struct addr linkLayer_dst;

	// Interface packet came from
	const struct interface *inter;

	// Used for TCP/UDP and ICMP
	// TODO: Using this for ICMP is hackish. Make it a union for type/code.
	uint16_t sport;
	uint16_t dport;

	int type;	/* Eiter SOCK_STREAM or SOCK_DGRAM */

	/* Statistics */
	uint32_t received;
	uint32_t sent;

	struct event* timeout;

	int local;	/* locally initiated */

	/* Potentially pending connection to subsystem */
	struct port_encapsulate *pending;
};



#endif /* TUPLE_H_ */
