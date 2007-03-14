/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _KEYCOUNT_H_
#define _KEYCOUNT_H_

struct keycount {
	SPLAY_ENTRY(keycount) node;

	const void *key;
	size_t keylen;

	void *auxilary;
	void (*aux_free)(void *);

	struct count *count;
};

int kc_compare(const struct keycount *a, const struct keycount *b);
SPLAY_HEAD(kctree, keycount);
SPLAY_PROTOTYPE(kctree, keycount, node, kc_compare);

struct keycount *keycount_new(const void *key, size_t len,
    void *(*)(void), void (*)(void *));
void keycount_free(struct keycount *);

/* Time-series keeping */

#define TIME_ENTRIES	64

struct timeentry {
	TAILQ_ENTRY(timeentry) next;

	struct timeval tv;
	uint32_t entries[TIME_ENTRIES];
	int nentries;
};

struct timekey {
	SPLAY_ENTRY(timekey) node;
	TAILQ_HEAD(timeq, timeentry) entries;

	void *key;
	size_t keylen;
};

SPLAY_HEAD(timetree, timekey);

struct kctree;
struct keycount;
struct timeseries {
	SPLAY_ENTRY(timeseries) node;
	SPLAY_ENTRY(timeseries) update_node;

	char *name;

	struct kctree *tree;
	void (*extract)(struct keycount *, void **, size_t *);
	void (*print)(void *, size_t);

	struct timeval tv_start;
	struct timeval tv_update;
	struct timeval tv_next;

	struct timetree entries;
};

void timeseries_init(void);
void timeseries_update(struct timeval *tv);

int key_compare(const void *a, size_t alen, const void *b, size_t blen);

#endif /* _KEYCOUNT_H_ */
