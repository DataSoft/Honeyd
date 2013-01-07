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

#include "tagging.h"
#include "histogram.h"
#include "analyze.h"
#include "filter.h"

/* Report filtering to select topN reports */
SPLAY_HEAD(filtertree, filter);

static int
filter_compare(struct filter *a, struct filter *b)
{
	if (a->count < b->count)
		return (-1);
	else if (a->count > b->count)
		return (1);

	if (a->report < b->report)
		return (-1);
	else if (a->report > b->report)
		return (1);
	return (0);
}

SPLAY_PROTOTYPE(filtertree, filter, node, filter_compare);
SPLAY_GENERATE(filtertree, filter, node, filter_compare);

struct filtertree *
filter_create(void)
{
	struct filtertree *filters;
	if ((filters = calloc(1, sizeof(struct filtertree))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc, failed to allocate filtertree",__func__);
		exit(EXIT_FAILURE);
	}

	SPLAY_INIT(filters);

	return (filters);
}

void
filter_free(struct filtertree *filters)
{
	struct filter *filter;

	while ((filter = SPLAY_ROOT(filters)) != NULL) {
		SPLAY_REMOVE(filtertree, filters, filter);
		free(filter);
	}
	free(filters);
}

/*
 * Inserts back reference and count into a filter tree.  Unfortunately,
 * this currently uses O(n log n) even though we are interested only in
 * the top<K> entries.
 */

void
filter_insert(struct filtertree *filters, uint32_t count, void *report)
{
	struct filter *filter, tmp;

	tmp.count = count;
	tmp.report = report;

	/* Check if we already manage this data */
	if ((filter = SPLAY_FIND(filtertree, filters, &tmp)) != NULL)
		return;

	if ((filter = calloc(1, sizeof(struct filter))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc failed to allocate filter",__func__);
		exit(EXIT_FAILURE);
	}

	filter->count = count;
	filter->report = report;
	SPLAY_INSERT(filtertree, filters, filter);
}

/* Filters out the top<n> entries */

void
filter_top(struct filtertree *filters, int n, void (*cb)(void *, void *),
    void *arg)
{
	int i = 0;
	struct filter *filter;

	while (i++ < n) {
		if ((filter = SPLAY_MAX(filtertree, filters)) == NULL ||
		    filter->count == 0)
			break;
		SPLAY_REMOVE(filtertree, filters, filter);

		(*cb)(filter->report, arg);
		free (filter);
	}
}
