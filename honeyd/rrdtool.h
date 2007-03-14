/*
 * Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _RRDTOOL_
#define _RRDTOOL_

struct rrdtool_command {
	TAILQ_ENTRY(rrdtool_command) next;

	char *command;

	void (*cb)(char *, void *);
	void *cb_arg;
};

#define MAX_RRD_DATASRCS	100

struct rrdtool_drv {
	int fd;
	pid_t pid;

	const char *bin_path;		/* path to the executeable */

	struct timeval tv_started;
	struct bufferevent *evb;

	struct event ev_timeout;
	
	TAILQ_HEAD(rrdtoolq, rrdtool_command) commands;
};

struct rrdtool_db {
	struct rrdtool_drv *drv;

	char rrd_file[512];

	char *datasrcs[MAX_RRD_DATASRCS];
	int ndatasrcs;

	char create_command[1024];	/* command used to create rrd */
};

int rrdtool_fork(struct rrdtool_drv *drv);

struct rrdtool_drv *rrdtool_init(const char *path_rrdtool);
void rrdtool_free(struct rrdtool_drv *);

void rrdtool_command(struct rrdtool_drv *, char *, void (*cb)(char *, void *), 
    void *);
void rrdtool_command_done(struct rrdtool_drv *, char *);

struct rrdtool_db *rrdtool_db_start(struct rrdtool_drv *, char *, int);
int rrdtool_db_datasource(struct rrdtool_db *, char *, char *, int);
int rrdtool_db_commit(struct rrdtool_db *db);
void rrdtool_db_free(struct rrdtool_db *db);

int rrdtool_db_update(struct rrdtool_db *db, struct timeval *tv, char *update);

void rrdtool_graph(struct rrdtool_db *, char *filename,
    struct timeval *, struct timeval *, char *spec);

void rrdtool_test();

#endif /* _RRDTOOL_ */
