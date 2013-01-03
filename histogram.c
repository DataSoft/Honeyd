/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/tree.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include <dnet.h>
#include <event.h>

#include "histogram.h"

static struct timeval *tv_now;	/* used for unittesting */

static struct event count_time_ev;
static struct timeval tv_periodic;

/*
 * We update our internal time via a periodic timeout.  This reduces the
 * number of system calls that we need to make for gettimeofday() without
 * reducing our accuracy too much.
 */

static void
count_time_evcb(int fd, short what, void *arg)
{
	struct event *ev = arg;
	struct timeval tv;

	gettimeofday(&tv_periodic, NULL);

	timerclear(&tv);
	tv.tv_sec = 1;
	evtimer_add(ev, &tv);
}

void
count_init(void)
{
	/* Start a timer that keeps track of the current system time */
	evtimer_set(&count_time_ev, count_time_evcb, &count_time_ev);
	count_time_evcb(-1, EV_TIMEOUT, &count_time_ev);
}

void
count_set_time(struct timeval *tv)
{
	tv_now = tv;
}

void
count_get_time(struct timeval *tv)
{
	if (tv_now == NULL)
		*tv = tv_periodic;
	else
		*tv = *tv_now;
}

struct count *
count_new(void)
{
	struct count *count;

	if ((count = calloc(1, sizeof(struct count))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc, failed to allocate count", __func__);
		exit(EXIT_FAILURE);
	}
		//err(1, "%s: calloc", __func__);

	count_get_time(&count->tv_seconds);

	count->tv_seconds.tv_usec = 0;
	count->tv_minutes = count->tv_seconds;
	count->tv_hours = count->tv_seconds;

	TAILQ_INIT(&count->seconds);
	TAILQ_INIT(&count->minutes);
	TAILQ_INIT(&count->hours);

	return (count);
}

void
count_entry_free(struct entryq *entries)
{
	struct entry *entry;

	for (entry = TAILQ_FIRST(entries);
	    entry != NULL;
	    entry = TAILQ_FIRST(entries)) {
		TAILQ_REMOVE(entries, entry, next);
		free(entry);
	}
}

void
count_free(struct count *count)
{
	count_entry_free(&count->seconds);
	count_entry_free(&count->minutes);
	count_entry_free(&count->hours);
}

void
count_move_entries(struct entryq *current, struct entryq *future,
    int incr, int max)
{
	struct entry *entry, *next;

	assert(incr >= 0);

	if (!incr)
		return;

	for (entry = TAILQ_FIRST(current); entry != NULL; entry = next) {
		next = TAILQ_NEXT(entry, next);

		entry->age += incr;

		/*
		 * If we are over the max then we need to move it to
		 * the next state.
		 */
		if (entry->age >= max) {
			TAILQ_REMOVE(current, entry, next);
			entry->age = 0;

			/* Merge with the first entry if possible */
			if (future != NULL) {
				struct entry *tmp = TAILQ_FIRST(future);
				if (tmp != NULL && tmp->age == 0) {
					tmp->count += entry->count;
					free(entry);
				} else {
					TAILQ_INSERT_HEAD(future, entry, next);
				}
			} else {
				/* Drop if it is too old for us to bother */
				free(entry);
			}
		}
	}

}

void
count_internal_increment(struct count *count, struct timeval *tv, int delta)
{
	struct timeval diff;
	struct entry *entry;
	
	/* Adjust the second buckets */
	timersub(tv, &count->tv_seconds, &diff);
	assert(diff.tv_sec >= 0);
	count_move_entries(&count->seconds, &count->minutes, diff.tv_sec, 60);

	/* Update the processing time */
	count->tv_seconds.tv_sec = tv->tv_sec;

	/* Adjust the minute buckets */
	timersub(tv, &count->tv_minutes, &diff);
	assert(diff.tv_sec >= 0);
	count_move_entries(&count->minutes, &count->hours,
	    diff.tv_sec / 60, 60);

	/* Update the minutes processing time without loosing precision */
	count->tv_minutes.tv_sec = tv->tv_sec - (diff.tv_sec % 60);

	/* Adjust the hour buckets */
	timersub(tv, &count->tv_hours, &diff);
	assert(diff.tv_sec >= 0);
	count_move_entries(&count->hours, NULL, diff.tv_sec / (60*60), 24);

	/* Update the hours processing time */
	count->tv_hours.tv_sec = tv->tv_sec - (diff.tv_sec % (60*60));

	/* We might have been called to just update the statistics */
	if (delta == 0)
		return;

	entry = TAILQ_FIRST(&count->seconds);
	if (entry != NULL && entry->age == 0) {
		entry->count += delta;
	} else {
		if ((entry = calloc(1, sizeof(struct entry))) == NULL)
		{
			syslog(LOG_ERR, "%s: calloc failed to allocate entry", __func__);
			exit(EXIT_FAILURE);
		}
			//err(1, "%s: calloc", __func__);
		entry->count = delta;
		TAILQ_INSERT_HEAD(&count->seconds, entry, next);
	}
}

void
count_increment(struct count *count, int delta)
{
	struct timeval *ptv = tv_now;
	
	if (ptv == NULL)
		ptv = &tv_periodic;

	// XXX timeseries_update(ptv);

	count_internal_increment(count, ptv, delta);
}

static void __inline
count_internal_print(FILE *fout, struct count *count, char *name)
{
	struct entry *entry;

	int minutes = 0;
	int hours = 0;
	int day = 0;

	TAILQ_FOREACH(entry, &count->seconds, next)
	    minutes += entry->count;
	TAILQ_FOREACH(entry, &count->minutes, next)
	    hours += entry->count;
	TAILQ_FOREACH(entry, &count->hours, next)
	    day += entry->count;

	fprintf(stderr, "%s: %6d %6d %6d\n", name, minutes, hours, day);
}

void
count_print(FILE *fout, struct count *count, char *name)
{
	/* Update the statistics */
	count_increment(count, 0);

	count_internal_print(fout, count, name);
}

uint32_t
count_get_sum(struct entryq *entries)
{
	struct entry *entry;
	uint32_t sum = 0;

	TAILQ_FOREACH(entry, entries, next)
	    sum += entry->count;

	return (sum);
}

uint32_t
count_get_minute(struct count *count)
{
	count_increment(count, 0);
	return (count_get_sum(&count->seconds));
}

uint32_t
count_get_hour(struct count *count)
{
	count_increment(count, 0);
	return (count_get_sum(&count->minutes));
}

uint32_t
count_get_day(struct count *count)
{
	count_increment(count, 0);
	return (count_get_sum(&count->hours));
}

void
count_test(void)
{
	struct count *count = count_new();
	struct timeval tv;
	int i;

	gettimeofday(&tv, NULL);
	
	count_internal_increment(count, &tv, 3);
	if (count_get_sum(&count->seconds) != 3)
	errx(1, "second count should be 1");

	tv.tv_sec += 61;

	count_internal_increment(count, &tv, 2);
	count_internal_increment(count, &tv, 0);

	if (count_get_sum(&count->seconds) != 2)
	errx(1, "second count should be 1");
	if (count_get_sum(&count->minutes) != 3)
	errx(1, "minute count should be 1");

	tv.tv_sec += 3540;
	count_internal_increment(count, &tv, 1);

	if (count_get_sum(&count->seconds) != 1)
	errx(1, "second count should be 1");
	if (count_get_sum(&count->minutes) != 2)
		errx(1, "minute count should be 1");
	if (count_get_sum(&count->hours) != 3)
	errx(1, "hour count should be 1");

	count_internal_print(stderr, count, "test-count");
	for (i = 0; i < 24; i++) {
		tv.tv_sec += 3600;
		count_internal_increment(count, &tv, 0);
	}
	count_internal_print(stderr, count, "test-count");
	if (count_get_sum(&count->seconds) ||
	    count_get_sum(&count->minutes) ||
	    count_get_sum(&count->hours))
		errx(1, "all counts should be zero");

	fprintf(stderr, "\t%s: OK\n", __func__);
}

/* Unittest related functionality */

void
histogram_test(void)
{
	count_test();
}
