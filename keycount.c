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

#include <sys/stat.h>
#include <syslog.h>
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>
#include <event.h>

#include "histogram.h"
#include "keycount.h"

/* Keycount related stuff */

int
key_compare(const void *a, size_t alen, const void *b, size_t blen)
{
	int keylen = MIN(alen, blen);
	int res;

	res = memcmp(a, b, keylen);
	if (res)
		return (res);

	return (alen - blen);
}

int
kc_compare(const struct keycount *a, const struct keycount *b)
{
	return (key_compare(a->key, a->keylen, b->key, b->keylen));
}

SPLAY_GENERATE(kctree, keycount, node, kc_compare);

struct keycount *
keycount_new(const void *key, size_t len,
    void *(*create)(void), void (*free)(void *))
{
	struct keycount *keycount;

	if ((keycount = calloc(1, sizeof(struct keycount))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc, failed to allocate keycount",__func__);
		exit(EXIT_FAILURE);
	}

	if ((keycount->key = malloc(len)) == NULL)
	{
		syslog(LOG_ERR, "%s: malloc",__func__);
		exit(EXIT_FAILURE);
	}

	keycount->keylen = len;
	memcpy((void *)keycount->key, key, len);

	keycount->count = count_new();

	if (create != NULL) {
		keycount->auxilary = (*create)();
		keycount->aux_free = free;
	}

	return (keycount);
}

void
keycount_free(struct keycount *kc)
{
	if (kc->auxilary != NULL && kc->aux_free != NULL)
		(*kc->aux_free)(kc->auxilary);
	free((void *)kc->key);
	count_free(kc->count);
	free(kc);
}

/* Timeseries related functionality */

static int
timekey_compare(struct timekey *a, struct timekey *b)
{
	return (key_compare(a->key, a->keylen, b->key, b->keylen));
}

SPLAY_PROTOTYPE(timetree, timekey, node, timekey_compare);
SPLAY_GENERATE(timetree, timekey, node, timekey_compare);

SPLAY_HEAD(timeseriestree, timeseries) timeviews;
SPLAY_HEAD(timeupdatetree, timeseries) timeupdates;

static int
timeseries_compare(struct timeseries *a, struct timeseries *b)
{
	return (strcmp(a->name, b->name));
}

SPLAY_PROTOTYPE(timeseriestree, timeseries, node, timeseries_compare);
SPLAY_GENERATE(timeseriestree, timeseries, node, timeseries_compare);

static int
timeupdate_compare(struct timeseries *a, struct timeseries *b)
{
	if (timercmp(&a->tv_next, &b->tv_next, <))
		return (-1);
	if (timercmp(&a->tv_next, &b->tv_next, >))
		return (1);

	if (a < b)
		return (-1);
	if (a > b)
		return (1);

	return (0);
}

SPLAY_PROTOTYPE(timeupdatetree, timeseries, update_node, timeupdate_compare);
SPLAY_GENERATE(timeupdatetree, timeseries, update_node, timeupdate_compare);

void
timeseries_init()
{
	SPLAY_INIT(&timeviews);
	SPLAY_INIT(&timeupdates);
}

struct timeseries *
timeseries_new(char *name, struct kctree *kct, 	void (*extract)(struct keycount *, void **, size_t *),	void (*print)(void *, size_t), struct timeval *update)
{
	struct timeseries tmp, *ts;

	tmp.name = name;
	if ((SPLAY_FIND(timeseriestree, &timeviews, &tmp)) != NULL)
		return (NULL);

	if ((ts = calloc(1, sizeof(struct timeseries))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc", __func__);
		exit(EXIT_FAILURE);
	}
	if ((ts->name = strdup(name)) == NULL)
	{
		syslog(LOG_ERR, "%s: strdup", __func__);
		exit(EXIT_FAILURE);
	}

	ts->extract = ts->extract;
	ts->print = ts->print;

	count_get_time(&ts->tv_start);

	ts->tv_update = *update;
	timeradd(&ts->tv_start, &ts->tv_update, &ts->tv_next);

	SPLAY_INIT(&ts->entries);

	SPLAY_INSERT(timeseriestree, &timeviews, ts);
	SPLAY_INSERT(timeupdatetree, &timeupdates, ts);

	return (ts);
}

struct timekey *
timekey_new(const void *key, size_t keylen)
{
	struct timekey *tk;

	if ((tk = calloc(1, sizeof(struct timekey))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc",__func__);
		exit(EXIT_FAILURE);
	}
	if ((tk->key = malloc(keylen)) == NULL)
	{
		syslog(LOG_ERR, "%s: malloc",__func__);
		exit(EXIT_FAILURE);
	}
	memcpy(tk->key, key, keylen);
	tk->keylen = keylen;

	TAILQ_INIT(&tk->entries);

	return (tk);
}

void
timeseries_update_item(struct timeseries *ts)
{
	struct keycount *kc;
	struct timekey *tk, tmp;

	SPLAY_FOREACH(kc, kctree, ts->tree) {
		/* Update the counters to our current time period */
		count_internal_increment(kc->count, &ts->tv_next, 0);

		tmp.key = (void *)kc->key;
		tmp.keylen = kc->keylen;
		if ((tk = SPLAY_FIND(timetree, &ts->entries, &tmp)) == NULL) {
			tk = timekey_new(kc->key, kc->keylen);
			SPLAY_INSERT(timetree, &ts->entries, tk);
		}

		/* Summarize and then record */
	}
}

void
timeseries_update(struct timeval *tv)
{
	struct timeseries *ts;

	for (ts = SPLAY_MIN(timeupdatetree, &timeupdates);
	    ts != NULL && timercmp(&ts->tv_next, tv, >);
	    ts = SPLAY_MIN(timeupdatetree, &timeupdates)) {
		SPLAY_REMOVE(timeupdatetree, &timeupdates, ts);

		timeseries_update_item(ts);

		timeradd(&ts->tv_next, &ts->tv_update, &ts->tv_next);

		SPLAY_INSERT(timeupdatetree, &timeupdates, ts);
	}
}
