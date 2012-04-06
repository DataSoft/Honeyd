/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _HISTOGRAM_H_
#define _HISTOGRAM_H_

/*
 * Inspired by
 * www.dar.csiro.au/rs/activeTcl/ActiveTcl8.3.4.2-html/tcllib/stats.n.html
 */

struct entry {
	TAILQ_ENTRY(entry) next;
	uint32_t age;
	uint32_t count;
};

TAILQ_HEAD(entryq, entry);

/*
 * We keep three different queues: seconds, minutes and hours each with their
 * own granularity.  Every time a new count is inserted, we bump the existing
 * entries up depending on how much time has passed between them.
 */

struct count {
	struct timeval tv_seconds;
	struct timeval tv_minutes;
	struct timeval tv_hours;
	struct entryq seconds;
	struct entryq minutes;
	struct entryq hours;
};

void count_init(void);
struct count *count_new(void);
void count_free(struct count *count);
void count_increment(struct count *count, int delta);
void count_internal_increment(struct count *, struct timeval *, int);
void count_get_time(struct timeval *tv);

void count_print(FILE *fout, struct count *count, char *name);

uint32_t count_get_minute(struct count *count);
uint32_t count_get_hour(struct count *count);
uint32_t count_get_day(struct count *count);

void count_set_time(struct timeval *);

void histogram_test(void);

#endif /* _HISTOGRAM_H_ */
