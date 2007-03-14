/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _FILTER_H_
#define _FILTER_H_

/*
 * Very simple filtering based on a count.  We insert the count and a
 * back-pointer for all keys and then select the top numbers.
 */

struct report;
struct filter {
	SPLAY_ENTRY(filter) node;
	uint32_t count;
	void *report;
};

struct filtertree;
struct filtertree *filter_create(void);
void filter_free(struct filtertree *);
void filter_insert(struct filtertree *filters, uint32_t count, void *report);
void filter_top(struct filtertree *filters, int n,
    void (*cb)(void *, void *), void *);

#endif /* _FILTER_H_ */
