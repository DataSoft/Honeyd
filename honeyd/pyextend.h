/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _PYEXTEND_
#define _PYEXTEND_

struct tuple;
struct command;
struct pystate;
struct evbuffer;

void pyextend_init(void);
void pyextend_exit(void);

#define PYEXTEND_MAX_REQUEST_SIZE	16384

void pyextend_webserver_init(char *address, int port, char *root_dir);
void pyextend_webserver_exit(void);
void pyextend_webserver_verify_setup(const char *);
void pyextend_webserver_fix_permissions(const char *, uid_t, gid_t);

int pyextend_connection_start(struct tuple *, struct command *, void *arg,
    void *pye);
struct pystate;
void pyextend_connection_end(struct pystate *);
void *pyextend_load_module(const char *);
void pyextend_run(struct evbuffer *output, char *command);

struct evbuffer;
struct pyextend_request {
	int fd;
	struct addr src;
	struct bufferevent *evb;
};

#endif /* _PYEXTEND_ */
