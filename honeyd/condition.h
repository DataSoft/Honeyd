/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _CONDITION_
#define _CONDITION_

struct template;
struct ip_hdr;

/* Conditonal template container */

struct condition {
	TAILQ_ENTRY(condition) next;

	int (*match)(const struct template *, const struct ip_hdr *, u_short, void *);
	void *match_arg;
	size_t match_arglen;
	
	struct template *tmpl;
};

struct timeval;
struct condition_time {
	struct tm tm_start;
	struct tm tm_end;
};

int condition_match_osfp(const struct template *, const struct ip_hdr *, u_short, void *);
int condition_match_addr(const struct template *, const struct ip_hdr *, u_short, void *);
int condition_match_time(const struct template *, const struct ip_hdr *, u_short, void *);
int condition_match_proto(const struct template *, const struct ip_hdr *, u_short, void *);
int condition_match_otherwise(const struct template *, const struct ip_hdr *, u_short, void *);

#endif /* _CONDITION_ */
