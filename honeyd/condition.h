/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
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
