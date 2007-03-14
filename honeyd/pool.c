/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#include <sys/types.h>
#include <sys/param.h>

#include "config.h"

#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "pool.h"

struct pool*
pool_init(size_t size)
{
	struct pool *pool;

	if (POOL_PAGE_SIZE / (sizeof(struct pool_entry) + size) < 1)
		errx(1, "%s: object size too large for pool", __func__);

	if ((pool = calloc(1, sizeof(struct pool))) == NULL)
		err(1, "%s: calloc", __func__);

	SLIST_INIT(&pool->entries);
	pool->size = size;

	return (pool);
}

void *
pool_alloc_size(struct pool *pool, size_t size)
{
	struct pool_entry *entry = NULL;

	if (size) {
		entry = malloc(size + sizeof(struct pool_entry));
		if (entry == NULL)
			err(1, "%s: malloc", __func__);
		
		entry->data = (void *)entry + sizeof(struct pool_entry);;
		entry->size = size;
		pool->nalloc++;
	} else {
		void *p = malloc(POOL_PAGE_SIZE);
		int i, max;

		if (p == NULL)
			err(1, "%s: malloc", __func__);

		size = pool->size;
		max = POOL_PAGE_SIZE / (sizeof(struct pool_entry) + size);
		pool->nalloc += max;
		for (i = 0; i < max; i++) {
			entry = p;
			entry->data = (void *)entry+ sizeof(struct pool_entry);
			entry->size = size;

			/* We want to use the last one as return */
			if (i < max - 1) {
				SLIST_INSERT_HEAD(&pool->entries, entry, next);
				p += sizeof(struct pool_entry) + size;
			}
		}
	}

	return (entry->data);
}
