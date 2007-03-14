/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _UTIL_H_
#define _UTIL_H_

/* File descriptor sharing */

int fdshare_dup(int);
int fdshare_close(int);
int fdshare_inspect(int);	/* for debugging */

extern int trace_on;
int trace_enter(int, char *, int);
struct evbuffer;
int trace_inspect(int, struct evbuffer *buffer);
void trace_onoff(int);

/* Simple tracing of fd activity */
#define TRACE(x, y) do { \
	if (trace_on) { \
		char *line = NULL; \
		asprintf(&line, "%s:%d: fd %d: %s", \
		    __FILE__, __LINE__, (x), #y); \
		trace_enter(x, line, 0); \
	} \
	y; \
} while (0)

#define TRACE_RESET(x, y) do { \
	if (trace_on) { \
		char *line = NULL; \
		asprintf(&line, "%s:%d: fd %d: %s", \
		    __FILE__, __LINE__, (x), #y); \
		trace_enter(x, line, 1); \
	} \
	y; \
} while (0)

/* Dictionary functions */
struct keyvalue {
	char *key;
	char *value;

	TAILQ_ENTRY(keyvalue) next;
};

TAILQ_HEAD(keyvalueq, keyvalue);

void kv_add(struct keyvalueq *head, char *key, char *value);
char *kv_find(struct keyvalueq *head, char *key);
int kv_remove(struct keyvalueq *head, char *key);
void kv_replace(struct keyvalueq *head, char *key, char *value);

/* Other misc stuff */
int make_bound_connect(int, char *, uint16_t, char *);
int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *address, uint16_t port);
void name_from_addr(struct sockaddr *sa, socklen_t salen,
    char **phost, char **pport);

/* Utility functions */
struct addr;
int addr_contained(struct addr *, struct addr *);
char *strrpl(char *, size_t, char *, char *);
char *fgetln(FILE *, size_t *);
char *strnsep(char **line, char *delim);

#endif /* _UTIL_H_ */
