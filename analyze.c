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
#include <sys/queue.h>
#include <sys/tree.h>
#include <syslog.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>
#include <event.h>
#include <evdns.h>

#include "honeydstats.h"
#include "tagging.h"
#include "histogram.h"
#include "keycount.h"
#include "analyze.h"
#include "filter.h"

char *os_report_file = NULL;
char *port_report_file = NULL;
char *spammer_report_file = NULL;
char *country_report_file = NULL;

static int checkpoint_doreplay;		/* externally set by honeydstats */

struct kctree oses;
struct kctree ports;
struct kctree spammers;
struct kctree countries;
struct kctree country_cache;

#define ROL64(x, b)	(((x) << b) | ((x) >> (64 - b)))
#define ROR64(x, b)	(((x) >> b) | ((x) << (64 - b)))

/* 
 * Thomas Wang's 64-bit hash function from 
 *   www.concentric.net/~Ttwang/tech/inthash.htm
 */
static __inline uint64_t
longhash1(uint64_t key)
{
  key += ~(key << 32);
  key ^= ROR64(key, 22);
  key += ~(key << 13);
  key ^= ROR64(key, 8);
  key += (key << 3);
  key ^= ROR64(key, 15);
  key += ~(key << 27);
  key ^= ROR64(key, 31);
  return key;
}

static __inline uint32_t
port_hash(const struct addr *src, const struct addr *dst)
{
	uint32_t a = src->addr_ip;
	uint32_t b = dst->addr_ip;
	return ((uint32_t)(longhash1(((uint64_t)a << 32) | b)));
}

void
port_key_extract(struct keycount *keycount, void **pkey, size_t *pkeylen)
{
	if ((*pkey = calloc(1, sizeof(uint16_t))) == NULL)
	{
		syslog(LOG_ERR, "calloc");
		exit(EXIT_FAILURE);
	}
	memcpy(*pkey, keycount->key, sizeof(uint16_t));
	*pkeylen = sizeof(uint16_t);
}

char *
port_key_print(void *key, size_t keylen)
{
	static char sport[7];
	snprintf(sport, sizeof(sport), "%d", *(uint16_t *)key);
	return (sport);
}

void
spammer_key_extract(struct keycount *keycount, void **pkey, size_t *pkeylen)
{
	if ((*pkey = calloc(1, keycount->keylen)) == NULL)
	{
		syslog(LOG_ERR, "calloc");
		exit(EXIT_FAILURE);
	}
	memcpy(*pkey, keycount->key, keycount->keylen);
	*pkeylen = keycount->keylen;
}

char *
spammer_key_print(void *key, size_t keylen)
{
	struct addr addr;
	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, key, IP_ADDR_LEN);
	return (addr_ntoa(&addr));
}

void
country_key_extract(struct keycount *keycount, void **pkey, size_t *pkeylen)
{
	if ((*pkey = calloc(1, keycount->keylen)) == NULL)
	{
		syslog(LOG_ERR, "calloc, failed to allocate the pkey");
		exit(EXIT_FAILURE);
	}
	memcpy(*pkey, keycount->key, keycount->keylen);
	*pkeylen = keycount->keylen;
}

char *
country_key_print(void *key, size_t keylen)
{
	return (key);
}

struct aux {
	SPLAY_HEAD(auxtree, auxkey) tree;
	TAILQ_HEAD(auxq, auxkey) queue;
	int limit;
	int entries;
};

static int
aux_compare(struct auxkey *a, struct auxkey *b)
{
	if (a->value < b->value)
		return (-1);
	if (a->value > b->value)
		return (1);
	return (0);
}

SPLAY_PROTOTYPE(auxtree, auxkey, node, aux_compare);
SPLAY_GENERATE(auxtree, auxkey, node, aux_compare);

void *
aux_create(void)
{
	struct aux *aux;

	if ((aux = calloc(1, sizeof(struct aux))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc failed to allocate aux",__func__);
		exit(EXIT_FAILURE);
	}
	SPLAY_INIT(&aux->tree);
	TAILQ_INIT(&aux->queue);
	aux->limit = 100000;	/* Make better at some point */

	return (aux);
}

void
aux_free(void *arg)
{
	struct aux *aux = arg;
	struct auxtree *tree = &aux->tree;
	struct auxkey *key;

	while ((key = SPLAY_ROOT(tree)) != NULL) {
		SPLAY_REMOVE(auxtree, tree, key);
		free(key);
	}
	free(arg);
}

/* Returns one if the key is new */

int
aux_enter(struct aux *aux, uint32_t value)
{
	struct auxtree *tree = &aux->tree;
	struct auxq *queue = &aux->queue;
	struct auxkey tmp, *key;

	tmp.value = value;
	if ((key = SPLAY_FIND(auxtree, tree, &tmp)) != NULL) {
		/* Mark this entry as recently used - LRU fashion */
		TAILQ_REMOVE(queue, key, next);
		TAILQ_INSERT_HEAD(queue, key, next);
		return (0);
	}

	if (aux->entries >= aux->limit) {
		key = TAILQ_LAST(queue, auxq);

		/* The old entry has to go, bye bye */
		SPLAY_REMOVE(auxtree, tree, key);
		TAILQ_REMOVE(queue, key, next);
		memset(key, 0, sizeof(struct auxkey));
		aux->entries--;
	} else {
		if ((key = calloc(1, sizeof(struct auxkey))) == NULL)
		{
			syslog(LOG_ERR, "%s: calloc failed to allocate key",__func__);
			exit(EXIT_FAILURE);
		}
	}
	key->value = tmp.value;

	/* Insert the new key */
	SPLAY_INSERT(auxtree, tree, key);
	TAILQ_INSERT_TAIL(queue, key, next);
	aux->entries++;

	return (1);
}

void
os_key_extract(struct keycount *keycount, void **pkey, size_t *pkeylen)
{
	const char *key = keycount->key;

	if ((*pkey = strdup(key)) == NULL)
	{
		syslog(LOG_ERR, "%s: strdup",__func__);
		exit(EXIT_FAILURE);
	}
	*pkeylen = strlen(key) + 1;
}

char *
os_key_print(void *key, size_t keylen)
{
	return (key);
}

static int
report_compare(struct report *a, struct report *b)
{
	return (key_compare(a->key, a->keylen, b->key, b->keylen));
}

SPLAY_HEAD(reporttree, report);
SPLAY_PROTOTYPE(reporttree, report, node, report_compare);
SPLAY_GENERATE(reporttree, report, node, report_compare);

void
analyze_init(void)
{
	struct timeval tv;
	timerclear(&tv);
	tv.tv_sec = ANALYZE_REPORT_INTERVAL; 

	struct event *ev_analyze = evtimer_new(stats_libevent_base, analyze_report_cb, NULL);
	evtimer_add(ev_analyze, &tv);

	SPLAY_INIT(&oses);
	SPLAY_INIT(&ports);
	SPLAY_INIT(&spammers);
	SPLAY_INIT(&countries);
	SPLAY_INIT(&country_cache);

	evdns_init();
}

void
analyze_set_checkpoint_doreplay(int doit)
{
	checkpoint_doreplay = doit;
}

void
analyze_record(const struct record *record)
{
	if (record->dst_port == 25 && record->bytes != 0)
		analyze_spammer_enter(&record->src, record->bytes);

	/* 
	 * Records may be duplicated if they carry extra payload hashes.
	 * In those cases, we need to ignore the connection information.
	 * We also want to ignore connection information for connections
	 * that were generated by the honeypots.
	 */
	if ((record->state & RECORD_STATE_NEW) == 0 ||
	    (record->flags & REC_FLAG_LOCAL) != 0)
		return;

	/* Enter OS fingerprint */
	if (record->os_fp == NULL)
		analyze_os_enter(&record->src, "unknown");
	else
		analyze_os_enter(&record->src, record->os_fp);

	/* Enter Port Analysis */
	analyze_port_enter(record->dst_port, &record->src, &record->dst);

	/* Entry country analysis */
	analyze_country_enter(&record->src, &record->dst);
}

void
analyze_spammer_enter(const struct addr *src, uint32_t bytes)
{
	struct keycount tmpkey, *key;

	tmpkey.key = &src->addr_ip;
	tmpkey.keylen = sizeof(src->addr_ip);

	if ((key = SPLAY_FIND(kctree, &spammers, &tmpkey)) == NULL) {
		key = keycount_new(&src->addr_ip, sizeof(src->addr_ip),
		    NULL, NULL);
		SPLAY_INSERT(kctree, &spammers, key);
	}

	count_increment(key->count, bytes);
}

struct country_state {
	struct addr src;
	struct addr dst;
	int result_from_cache;
};

void
analyze_country_enter_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct country_state *state = arg;
	struct addr *src = &state->src;
	struct keycount tmpkey, *key;
	char tld[20];

	if (result != DNS_ERR_NONE || count != 1 || type != DNS_PTR) {
		/* Enter into our negative cache */
		if (!state->result_from_cache) {
			tmpkey.key = &src->addr_ip;
			tmpkey.keylen = sizeof(src->addr_ip);
			key = SPLAY_FIND(kctree, &country_cache, &tmpkey);
			if (!key) {
				key = keycount_new(
					&src->addr_ip,
					sizeof(src->addr_ip),
					NULL, NULL);
				SPLAY_INSERT(kctree, &country_cache, key);
			}
			count_increment(key->count, 1);
		}

		strlcpy(tld, "unknown", sizeof(tld));
	} else {
		const char *hostname = *(char **)addresses;
		int i;
		/* Extract the country key */
		for (i = strlen(hostname) - 1; i >= 0; --i) {
			if (hostname[i] == '.') {
				i += 1;
				break;
			}
		}

		strlcpy(tld, hostname + i, sizeof(tld));
		for (i = 0; i < strlen(tld); i++) {
			if (isdigit(tld[i])) {
				strlcpy(tld, "unknown", sizeof(tld));
				break;
			}
			tld[i] = tolower(tld[i]);
		}
	}

	tmpkey.key = tld;
	tmpkey.keylen = strlen(tmpkey.key) + 1;
	if ((key = SPLAY_FIND(kctree, &countries, &tmpkey)) == NULL) {
		key = keycount_new(tld, strlen(tld) + 1, aux_create, aux_free);
		SPLAY_INSERT(kctree, &countries, key);
	}

	/* If the address is new, we are going to resolve it */
	if (aux_enter(key->auxilary, port_hash(&state->src, &state->dst)))
		count_increment(key->count, 1);
	free(state);
}

void
analyze_country_enter(const struct addr *addr, const struct addr *dst)
{
	struct keycount tmpkey, *key;

	struct country_state *state = calloc(1, sizeof(struct country_state));
	if (state == NULL)
	{
		syslog(LOG_ERR, "%s: failed to calloc state", __func__);
		exit(EXIT_FAILURE);
	}

	state->src = *addr;
	state->dst = *dst;

	/*
	 * Check if this IP returned a resolver error in the last hour.
	 */
	tmpkey.key = &addr->addr_ip;
	tmpkey.keylen = sizeof(addr->addr_ip);
	if ((key = SPLAY_FIND(kctree, &country_cache, &tmpkey)) != NULL) {
		if (count_get_minute(key->count) ||
		    count_get_hour(key->count)) {
			state->result_from_cache = 1;
			analyze_country_enter_cb(DNS_ERR_NOTEXIST, DNS_PTR,
			    0, 0, NULL, state);
			return;
		}
	}

	if (!checkpoint_doreplay) {
		struct in_addr in;
		in.s_addr = addr->addr_ip;
		evdns_resolve_reverse(&in, 0, analyze_country_enter_cb, state);
	} else {
		/*
		 * If we are replaying a checkpoint, we do not want to do
		 * async calls.
		 */
		struct hostent *hp = gethostbyaddr(
			(const char *)&addr->addr_ip, IP_ADDR_LEN, AF_INET);
		if (hp == NULL) {
			analyze_country_enter_cb(DNS_ERR_NOTEXIST, DNS_PTR,
			    0, 0, NULL, state);
		} else {
			analyze_country_enter_cb(DNS_ERR_NONE, DNS_PTR,
			    1, 1200 /* ttl */, (void *)&hp->h_name, state);
		}
	}
}

void
analyze_os_enter(const struct addr *addr, const char *osfp)
{
	struct keycount tmpkey, *key;

	tmpkey.key = osfp;
	tmpkey.keylen = strlen(osfp) + 1;

	if ((key = SPLAY_FIND(kctree, &oses, &tmpkey)) == NULL) {
		key = keycount_new(osfp, strlen(osfp) + 1,
		    aux_create, aux_free);
		SPLAY_INSERT(kctree, &oses, key);
	}

	/* If the address is new, we are going to increase the counter */
	if (aux_enter(key->auxilary, addr->addr_ip))
		count_increment(key->count, 1);
}

void
analyze_port_enter(uint16_t port,
    const struct addr *src, const struct addr *dst)
{
	struct keycount tmpkey, *key;

	tmpkey.key = &port;
	tmpkey.keylen = sizeof(port);

	if ((key = SPLAY_FIND(kctree, &ports, &tmpkey)) == NULL) {
		key = keycount_new(&port, sizeof(port),
		    aux_create, aux_free);
		SPLAY_INSERT(kctree, &ports, key);
	}

	/* If the address is new, we are going to increase the counter */
	if (aux_enter(key->auxilary, port_hash(src, dst)))
		count_increment(key->count, 1);
}

void
report_to_file(struct reporttree *tree, char *filename,
    char *(*print)(void *, size_t))
{
	static char line[1024];
	FILE *fout;

	/* We do not create report files while we are replaying a checkpoint */
	if (checkpoint_doreplay)
		return;

	/* create a temporary file */
	strlcpy(line, filename, sizeof(line));
	strlcat(line, ".tmp", sizeof(line));

	if ((fout = fopen(line, "w")) != NULL) {
		report_print(tree, fout, print);
		fclose(fout);
		/* This is an atomic operation */
		rename(line, filename);
		chmod(filename, S_IRWXU | S_IRGRP | S_IROTH);
	} else {
		warn("%s: fopen('%s')", __func__, line);
	}
}

void
report_print(struct reporttree *tree, FILE *out, 
    char *(*print)(void *, size_t))
{
	struct report *report;

	/* Now print the information in alphabetical order */
	SPLAY_FOREACH(report, reporttree, tree) {
		fprintf(out, "%25s: %7d %7d %7d\n",
		    print(report->key, report->keylen),
		    report->minute, report->hour, report->day);
	}
}

void
report_free(struct reporttree *tree)
{
	struct report *report;

	/* And then free the whole tree */
	while ((report = SPLAY_ROOT(tree)) != NULL) {
		SPLAY_REMOVE(reporttree, tree, report);

		free(report->key);
		free(report);
	}
	free(tree);
}

struct reporttree *
report_create(struct kctree *kctree,
    void (*extract)(struct keycount *, void **, size_t *))
{
	struct reporttree *tree;
	struct report *report;
	struct keycount *kc, *next;

	if ((tree = calloc(1, sizeof(struct reporttree))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc", __func__);
		exit(EXIT_FAILURE);
	}

	SPLAY_INIT(tree);

	for (kc = SPLAY_MIN(kctree, kctree); kc != NULL; kc = next) {
		struct report tmp;
		uint32_t sum = 0;

		next = SPLAY_NEXT(kctree, kctree, kc);
		
		(*extract)(kc, &tmp.key, &tmp.keylen);
		if ((report = SPLAY_FIND(reporttree, tree, &tmp)) == NULL) {
			report = calloc(1, sizeof(struct report));
			if (report == NULL)
			{
				syslog(LOG_ERR, "%s: calloc",__func__);
				exit(EXIT_FAILURE);
			}
			report->key = tmp.key;
			report->keylen = tmp.keylen;
			SPLAY_INSERT(reporttree, tree, report);
		}

		/* Now get the data together */
		if ((sum = count_get_minute(kc->count)) != 0)
			report->minute += sum;
		if ((sum += count_get_hour(kc->count)) != 0)
			report->hour += sum;
		if ((sum += count_get_day(kc->count)) != 0)
			report->day += sum;

		if (!sum) {
			SPLAY_REMOVE(kctree, kctree, kc);
			keycount_free(kc);
		}
	}

	return (tree);
}

void
make_report(struct kctree *kctree, char *filename,
    void (*extract)(struct keycount *, void **, size_t *),
    char *(*print)(void *, size_t))
{
	struct reporttree *tree = report_create(kctree, extract);

	report_print(tree, stderr, print);

	if (filename != NULL)
		report_to_file(tree, filename, print);

	report_free(tree);
}

struct filterarg {
	struct reporttree *src;
	struct reporttree *dst;
};

void
analyze_filter_cb(void *reparg, void *treearg)
{
	struct report *report = reparg;
	struct filterarg *fa = treearg;

	if (SPLAY_FIND(reporttree, fa->dst, report) != NULL)
		return;

	SPLAY_REMOVE(reporttree, fa->src, report);
	SPLAY_INSERT(reporttree, fa->dst, report);
}

void
analyze_print_port_report()
{
	struct reporttree *tree, *filtered_tree;
	struct filtertree *min_filters, *hour_filters, *day_filters;
	struct report *report;
	struct filterarg fa;

	tree = report_create(&ports, port_key_extract);

	/* Filter trees for Minutes, Hours and Days */
	min_filters = filter_create();
	hour_filters = filter_create();
	day_filters = filter_create();
	SPLAY_FOREACH(report, reporttree, tree) {
		filter_insert(min_filters, report->minute, report);
		filter_insert(hour_filters, report->hour, report);
		filter_insert(day_filters, report->day, report);
	}

	if ((filtered_tree = calloc(1, sizeof(struct reporttree))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc failed to allocate filtered_tree",__func__);
		exit(EXIT_FAILURE);
	}
	SPLAY_INIT(filtered_tree);

	/* 
	 * Object passed to the call back function to  merge the different
	 * filter trees.
	 */
	fa.src = tree;
	fa.dst = filtered_tree;

	filter_top(min_filters, 5, analyze_filter_cb, &fa);
	filter_top(hour_filters,10, analyze_filter_cb, &fa);
	filter_top(day_filters, 15, analyze_filter_cb, &fa);

	filter_free(min_filters);
	filter_free(hour_filters);
	filter_free(day_filters);
	report_free(tree);

	fprintf(stderr, "Destination Port Statistics\n");
	report_print(filtered_tree, stderr, port_key_print);

	if (port_report_file != NULL)
		report_to_file(filtered_tree, port_report_file,
		    port_key_print);

	report_free(filtered_tree);
}

void
analyze_print_spammer_report()
{
	struct reporttree *tree, *filtered_tree;
	struct filtertree *min_filters, *hour_filters, *day_filters;
	struct report *report;
	struct filterarg fa;

	tree = report_create(&spammers, spammer_key_extract);

	/* Filter trees for Minutes, Hours and Days */
	min_filters = filter_create();
	hour_filters = filter_create();
	day_filters = filter_create();
	SPLAY_FOREACH(report, reporttree, tree) {
		filter_insert(min_filters, report->minute, report);
		filter_insert(hour_filters, report->hour, report);
		filter_insert(day_filters, report->day, report);
	}

	if ((filtered_tree = calloc(1, sizeof(struct reporttree))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc failed to allocate filtered_tree",__func__ );
		exit(EXIT_FAILURE);
	}
	SPLAY_INIT(filtered_tree);

	/* 
	 * Object passed to the call back function to  merge the different
	 * filter trees.
	 */
	fa.src = tree;
	fa.dst = filtered_tree;

	filter_top(min_filters, 5, analyze_filter_cb, &fa);
	filter_top(hour_filters,10, analyze_filter_cb, &fa);
	filter_top(day_filters, 20, analyze_filter_cb, &fa);

	filter_free(min_filters);
	filter_free(hour_filters);
	filter_free(day_filters);
	report_free(tree);

	fprintf(stderr, "Spammer Address Statistics\n");
	report_print(filtered_tree, stderr, spammer_key_print);

	if (spammer_report_file != NULL)
		report_to_file(filtered_tree, spammer_report_file,
		    spammer_key_print);

	report_free(filtered_tree);
}

void
analyze_print_country_report()
{
	struct reporttree *tree, *filtered_tree;
	struct filtertree *min_filters, *hour_filters, *day_filters;
	struct report *report;
	struct filterarg fa;

	tree = report_create(&countries, country_key_extract);

	/* Filter trees for Minutes, Hours and Days */
	min_filters = filter_create();
	hour_filters = filter_create();
	day_filters = filter_create();
	SPLAY_FOREACH(report, reporttree, tree) {
		filter_insert(min_filters, report->minute, report);
		filter_insert(hour_filters, report->hour, report);
		filter_insert(day_filters, report->day, report);
	}

	if ((filtered_tree = calloc(1, sizeof(struct reporttree))) == NULL)
	{
		syslog(LOG_ERR, "%s: calloc failed to initialize failed tree",__func__);
		exit(EXIT_FAILURE);
	}
	SPLAY_INIT(filtered_tree);

	/* 
	 * Object passed to the call back function to  merge the different
	 * filter trees.
	 */
	fa.src = tree;
	fa.dst = filtered_tree;

	filter_top(min_filters, 5, analyze_filter_cb, &fa);
	filter_top(hour_filters,10, analyze_filter_cb, &fa);
	filter_top(day_filters, 20, analyze_filter_cb, &fa);

	filter_free(min_filters);
	filter_free(hour_filters);
	filter_free(day_filters);
	report_free(tree);

	fprintf(stderr, "Country Activity Statistics\n");
	report_print(filtered_tree, stderr, country_key_print);

	if (country_report_file != NULL)
		report_to_file(filtered_tree, country_report_file,
		    country_key_print);

	report_free(filtered_tree);
}

void
analyze_print_report()
{
	fprintf(stderr, "Operating System Statistics\n");
	make_report(&oses, os_report_file, os_key_extract, os_key_print);

	analyze_print_port_report();
	analyze_print_spammer_report();
	analyze_print_country_report();
}

void
analyze_report_cb(int fd, short what, void *unused)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = ANALYZE_REPORT_INTERVAL;

	struct event *ev = evtimer_new(stats_libevent_base, analyze_report_cb, NULL);
	evtimer_add(ev, &tv);

	analyze_print_report();
}

#define OS_NUM_OSES	12

void
os_test()
{
	char *fingerprints[OS_NUM_OSES] = {
		"Linux",
		"Windows",
		"NetBSD",
		"OpenBSD",
		"Windows",
		"Windows",
		"Linux",
		"Windows",
		"Linux",
		"OpenBSD",
		"FreeBSD",
		"unknown"
	};
	struct addr src;
	struct timeval tv;
	rand_t *rand = rand_open();
	int i, j;

	gettimeofday(&tv, NULL);
	count_set_time(&tv);

	addr_pton("127.0.0.1", &src);
	for (i = 0; i < 24 * 60 * 2 + 60 * 4; i++) {
		for (j = 0; i < 24 * 60 * 2 &&
		    j < rand_uint8(rand) % 50000 + 5000; j++) {
			src.addr_ip = rand_uint32(rand);
			analyze_os_enter(&src,
			    fingerprints[rand_uint8(rand) % OS_NUM_OSES]);
		}
		tv.tv_sec += 30;

		if (i % 120 == 0) {
			fprintf(stderr, "%ld:\n", tv.tv_sec);
			make_report(&oses, NULL, os_key_extract, os_key_print);
		}
	}

	if (SPLAY_ROOT(&oses) != NULL)
	{
		syslog(LOG_ERR,"oses fingerprints should have been purged");
		exit(EXIT_FAILURE);
	}

	count_set_time(NULL);

	rand_close(rand);
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
analyze_test(void)
{
	os_test();
}
