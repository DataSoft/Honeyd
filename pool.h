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

#ifndef _POOL_
#define _POOL_

#include <syslog.h>

#define POOL_PAGE_SIZE	4096

struct pool_entry {
	SLIST_ENTRY(pool_entry) next;
	void *data;
	size_t size;
};

struct pool {
	SLIST_HEAD(poolq, pool_entry) entries;
	size_t size;
	int nalloc;
};

struct pool *pool_init(size_t);
void *pool_alloc_size(struct pool *, size_t);

/* 
 * The pool interface cached allocation of fixed sized objects,
 * but it can also be used to allocate larger buffers if necessary.
 */

static __inline void *
pool_alloc(struct pool *pool)
{
	struct pool_entry *entry;

	if ((entry = SLIST_FIRST(&pool->entries)) == NULL)
		return (pool_alloc_size(pool, 0));

	SLIST_REMOVE_HEAD(&pool->entries, next);
	return (entry->data);
}

static __inline void
pool_free(struct pool *pool, void *addr)
{
	struct pool_entry *entry = addr - sizeof(struct pool_entry);

	if (entry->data != addr)
	{
		syslog(LOG_ERR, "%s: bad address: %p != %p", __func__, addr, entry->data);
		exit(EXIT_FAILURE);
	}
		//errx(1, "%s: bad address: %p != %p", __func__,
		  //  addr, entry->data);

	if (entry->size == pool->size)
		SLIST_INSERT_HEAD(&pool->entries, entry, next);
	else {
		free(entry);
		pool->nalloc--;
	}
}

#endif /* _POOL_ */
