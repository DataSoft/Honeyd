/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _ANALYZE_H_
#define _ANALYZE_H_

#define ANALYZE_REPORT_INTERVAL	60

struct auxkey {
	SPLAY_ENTRY(auxkey) node;
	TAILQ_ENTRY(auxkey) next;
	uint32_t value;
};

struct report {
	SPLAY_ENTRY(report) node;

	void *key;
	size_t keylen;

	uint32_t minute;
	uint32_t hour;
	uint32_t day;
};

struct record;
void analyze_init(void);
void analyze_set_checkpoint_doreplay(int);
void analyze_record(const struct record *record);
void analyze_report_cb(int, short, void *);

void analyze_spammer_enter(const struct addr *src, uint32_t bytes);
void analyze_os_enter(const struct addr *addr, const char *osfp);
void analyze_port_enter(uint16_t, const struct addr *, const struct addr *);
void analyze_country_enter(const struct addr *, const struct addr *);

struct kctree;
struct keycount;
struct reporttree *report_create(struct kctree *kctree,
    void (*extract)(struct keycount *, void **, size_t *));
void make_report(struct kctree *, char *,
    void (*)(struct keycount *, void **, size_t *),
    char *(*)(void *, size_t));
struct reporttree;
void report_free(struct reporttree *tree);
void report_print(struct reporttree *, FILE *,  char *(*)(void *, size_t));

void analyze_print_report();

void analyze_test(void);

#endif /* _ANALYZE_H_ */
