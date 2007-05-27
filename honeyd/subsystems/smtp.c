/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <netinet/in.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <sha1.h>

#include <event.h>
#include <evdns.h>

#include "util.h"
#include "smtp.h"
#include "smtp_messages.h"
#include "honeyd_overload.h"

extern int debug;

#define DFPRINTF(x, y)	do { \
	if (debug >= x) fprintf y; \
} while (0)

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);

/* globals */

FILE *flog_email = NULL;	/* log the email transactions somewhere */
const char *log_datadir = NULL;	/* log the data somewhere */

static char datadir_buf[1024];
static char getcwdbuf[1024];

static char *domains[] = {
	"iridic", "bocoy", "hers", "alfa", "chital", "sound", "razz",
	"update", "gown", "teeter", "embark", "valeta", "sipid", "whally",
	"dewcup", "shabby", "eral", "kibble", "samh", "artha", "zither",
	"bench", "duffel", "census", "hacker", "booger", "hobbil", "apish",
	"arris", "thyme", "stays", "begut", "unhid", "subgod", "genal",
	"fluty", "gossy", "skiver", "secque", "fetish", "osse", "dipyre",
	"germin", "datary", "muffle", "refuse", "semis", "vireo", "riser",
	"panada", "rackle", "dhyana", "crena", "upcall", "cumbu", "pinta",
	"finial", "euphon", "auxin", "voiced"
};

static char *hosts[] = {
	"neofetal", "theonomy", "panicked", "securely", "palgat", "rejoice",
	"teagle", "unkeyed", "calor", "overpick", "runefolk", "trend",
	"nunship", "leveling", "messe", "baetuli", "bossing", "mystic",
	"cnida", "premove", "brassily", "fossiled", "fibril", "marooner",
	"pataka", "bailee", "futurism", "tropate", "stuffer", "boost",
	"portitor", "tussah", "goatskin", "clition", "antiwit", "scind",
	"ruggedly", "chummer", "sloan", "mescal", "redub", "cozily",
	"drawout", "matin", "acetated", "mustang", "shuck", "bruscus",
	"yummy", "swiney", "snubby", "handrail", "centimo", "wind", "dog",
	"magic", "wonder"
};

int
smtp_set_datadir(const char *optarg)
{
	struct stat sb;

	getcwd(getcwdbuf, sizeof(getcwdbuf));

	if (*optarg != '/') {
		snprintf(datadir_buf, sizeof(datadir_buf),
		    "%s/%s", getcwdbuf, optarg);
		log_datadir = datadir_buf;
	} else {
		log_datadir = optarg;
	}
	if (stat(log_datadir, &sb) == -1 || (sb.st_mode & S_IFDIR) == 0)
		return (-1);

	return (0);
}

static char *
random_hostname(void)
{
	static char hostname[128];
	int domainindex, hostindex;

	domainindex = rand() % (sizeof(domains)/sizeof(char *));
	hostindex = rand() % (sizeof(hosts)/sizeof(char *));

	snprintf(hostname, sizeof(hostname), "%s.%s.com", 
	    hosts[hostindex], domains[domainindex]);

	return hostname;
}

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

/* Generic SMTP related code */

char *
smtp_logline(struct smtp_ta *ta)
{
	static char line[1024];
	struct keyvalue *entry;

	char *srcipaddress = kv_find(&ta->dictionary, "$srcipaddress");
	char *srcname = kv_find(&ta->dictionary, "$srcname");
	char *sender = kv_find(&ta->dictionary, "$sender");

	snprintf(line, sizeof(line), "%ld %s[%s]: %s ->",
	    time(NULL), srcipaddress, srcname, sender);

	TAILQ_FOREACH(entry, &ta->dictionary, next) {
		if (strcmp(entry->key, "$recipient"))
			continue;
		strlcat(line, " ", sizeof(line));
		strlcat(line, entry->value, sizeof(line));
	}

	return (line);
}

void
smtp_clear_state(struct smtp_ta *ta)
{
	ta->state = EXPECT_HELO;
	kv_remove(&ta->dictionary, "$sender");
	kv_remove(&ta->dictionary, "$srcname");
	kv_remove(&ta->dictionary, "$realuser");
	kv_remove(&ta->dictionary, "$vrfyuser");

	/* Remove all recipients */
	while (kv_remove(&ta->dictionary, "$recipient"))
		;
}

/* Callbacks for SMTP handling */

char *
smtp_response(struct smtp_ta *ta, struct keyvalue data[]) {
	static char line[1024];
	struct keyvalue *cur;

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(ta->mailer_id, cur->key) == 0)
			break;
	}

	if (cur->key == NULL)
		return (NULL);

	strlcpy(line, cur->value, sizeof(line));

	TAILQ_FOREACH(cur, &ta->dictionary, next) {
		strrpl(line, sizeof(line), cur->key, cur->value);
	}
	
	return (line);
}

void
smtp_handle_helo_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct smtp_ta *ta = arg;
	char *response;

	if (ta->dns_canceled) {
		smtp_ta_free(ta);
		return;
	}
	ta->dns_pending = 0;

	if (result == DNS_ERR_NONE && count == 1) {
		char *hostname = *(char **)addresses;
		kv_replace(&ta->dictionary, "$srcname", hostname);
	}

	response = smtp_response(ta, helo);
	bufferevent_write(ta->bev, response, strlen(response));

	ta->state = EXPECT_MAILFROM;
}

int
smtp_handle_helo(struct smtp_ta *ta, char *line)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&ta->sa;
	char *domainname;

	if (line == NULL) {
		char *response = smtp_response(ta, heloerror);
		bufferevent_write(ta->bev, response, strlen(response));
		return (0);
	}

	smtp_clear_state(ta);

	domainname = strsep(&line, " ");
	kv_replace(&ta->dictionary, "$srcname", domainname);

	evdns_resolve_reverse(&sin->sin_addr, 0, smtp_handle_helo_cb, ta);
	ta->dns_pending = 1;

	return (0);
}

int
smtp_handle_ehlo(struct smtp_ta *ta, char *line)
{
	char *domainname, *response;

	if (line == NULL) {
		response = smtp_response(ta, ehloerror);
		bufferevent_write(ta->bev, response, strlen(response));
		return (0);
	}

	smtp_clear_state(ta);

	domainname = strsep(&line, " ");
	kv_replace(&ta->dictionary, "$srcname", domainname);

	response = smtp_response(ta, ehlo);
	bufferevent_write(ta->bev, response, strlen(response));

	ta->state = EXPECT_MAILFROM;
	return (0);
}

int
smtp_handle_mailfrom(struct smtp_ta *ta, char *line)
{
	char *response;
	char *from = strsep(&line, " ");
	if (kv_find(&ta->dictionary, "$sender")) {
		response = smtp_response(ta, mailfromerror);
	} else {
		kv_add(&ta->dictionary, "$sender", from);
		response = smtp_response(ta, mailfrom);
		ta->state = EXPECT_RCPT;
	}

	bufferevent_write(ta->bev, response, strlen(response));
	return (0);
}

int
smtp_handle_rcpt(struct smtp_ta *ta, char *line)
{
	char *response;
	char *from = strsep(&line, " ");
	if (kv_find(&ta->dictionary, "$sender") == NULL) {
		response = smtp_response(ta, rcpttoerror);
	} else {
		kv_add(&ta->dictionary, "$recipient", from);
		response = smtp_response(ta, rcptto);
	}

	bufferevent_write(ta->bev, response, strlen(response));
	return (0);
}

int
smtp_handle_data(struct smtp_ta *ta, char *line)
{
	char *response;
	if (kv_find(&ta->dictionary, "$sender") == NULL) {
		response = smtp_response(ta, datanomail);
	} else if (kv_find(&ta->dictionary, "$recipient") == NULL) {
		response = smtp_response(ta, datanorcpt);
	} else {
		response = smtp_response(ta, data);
		ta->state = EXPECT_DATA;
	}

	bufferevent_write(ta->bev, response, strlen(response));
	return (0);
}

int
smtp_handle_quit(struct smtp_ta *ta, char *line)
{
	char *response;
	response = smtp_response(ta, quit);
	bufferevent_write(ta->bev, response, strlen(response));
	ta->wantclose = 1;
	return (0);
}

int
smtp_handle_help(struct smtp_ta *ta, char *line)
{
	char *response;

	if ( line != NULL ) {
		kv_replace(&ta->dictionary, "$helpask", line);
		response = smtp_response(ta, helperror);
	} else {
		response = smtp_response(ta, help);
	}

	bufferevent_write(ta->bev, response, strlen(response));
	return (0);
}

int
smtp_handle_noop(struct smtp_ta *ta, char *line)
{
	char *response;

	response = smtp_response(ta, noop);
	bufferevent_write(ta->bev, response, strlen(response));

	return (0);
}

int
smtp_handle_rset(struct smtp_ta *ta, char *line)
{
	char *response;

	response = smtp_response(ta, rset);
	bufferevent_write(ta->bev, response, strlen(response));

	smtp_clear_state(ta);

	return (0);
}

int
smtp_handle_vrfy(struct smtp_ta *ta, char *line)
{
	char *response;

	if (line == NULL || strlen(line) == 0) {
		response = smtp_response(ta, vrfyerror);
	} else {
		char *where = strchr(line, '@');
		if (where && strchr(where + 1, '.') != NULL) {
			/* This does not strip the braces, etc. */
			kv_replace(&ta->dictionary, "$realuser", line);
			response = smtp_response(ta, vrfy);
		} else {
			kv_replace(&ta->dictionary, "$vrfyuser", line);
			response = smtp_response(ta, vrfynouser);
		}
	}

	bufferevent_write(ta->bev, response, strlen(response));

	return (0);
}

int
smtp_handle_dot(struct smtp_ta *ta)
{
	char *response;
	
	if (strcmp(ta->mailer_id, "sendmail") == 0) {
		char *qchar = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx";
		char qspec[7], qnr[7+5+1];
		struct tm tm;
		time_t now = time(NULL);
		localtime_r(&now, &tm);

		qspec[0] = qchar[tm.tm_year % 60];
		qspec[1] = qchar[tm.tm_mon];
		qspec[2] = qchar[tm.tm_mday];
		qspec[3] = qchar[tm.tm_hour];
		qspec[4] = qchar[tm.tm_min];
		qspec[5] = qchar[tm.tm_sec];
		qspec[6] = '\0';

		snprintf(qnr, sizeof(qnr), "%s%05d", qspec, rand() % 100000);
		kv_replace(&ta->dictionary, "$queuenr", qnr);
	} else {
		char qnr[12];
		snprintf(qnr, sizeof(qnr), "%04X%06X",
		    rand() % 65536, rand() % (65536*256));
		kv_replace(&ta->dictionary, "$queuenr", qnr);
	}

	response = smtp_response(ta, dot);
	bufferevent_write(ta->bev, response, strlen(response));

	if (flog_email != NULL) {
		fprintf(flog_email, "%s\n", smtp_logline(ta));
		fflush(flog_email);
	}

	if (log_datadir != NULL) {
		smtp_store(ta, log_datadir);
	}

	smtp_clear_state(ta);

	return (0);
}

int
smtp_handle(struct smtp_ta *ta, char *line)
{
	char *command;

	if (ta->state == EXPECT_DATA) {
		/* Wait for the single dot */
		if (strcmp(line, ".") == 0) {
			smtp_handle_dot(ta);
		} else {
			kv_add(&ta->dictionary, "data", line);
		}
		return (0);
	}

	kv_replace(&ta->dictionary, "$cmd", line);

	command = strsep(&line, " ");
	/* Special case the commands with space in them */
	if (strcasecmp(command, "mail") == 0 ||
	    strcasecmp(command, "rcpt") == 0) {
		char *next = strsep(&line, " ");
		if (next != NULL)
			command[strlen(command)] = ' ';
	}

	if (strcasecmp(command, "HELO") == 0) {
		return (smtp_handle_helo(ta, line));
	} else if (strcasecmp(command, "EHLO") == 0) {
		return (smtp_handle_ehlo(ta, line));
	} else if (strcasecmp(command, "MAIL FROM:") == 0 &&
	    line != NULL && strlen(line)) {
		return (smtp_handle_mailfrom(ta, line));
	} else if (strcasecmp(command, "RCPT TO:") == 0 &&
	    line != NULL && strlen(line)) {
		return (smtp_handle_rcpt(ta, line));
	} else if (strcasecmp(command, "DATA") == 0) {
		return (smtp_handle_data(ta, line));
	} else if (strcasecmp(command, "HELP") == 0) {
		return (smtp_handle_help(ta, line));
	} else if (strcasecmp(command, "QUIT") == 0) {
		return (smtp_handle_quit(ta, line));
	} else if (strcasecmp(command, "NOOP") == 0) {
		return (smtp_handle_noop(ta, line));
	} else if (strcasecmp(command, "RSET") == 0) {
		return (smtp_handle_rset(ta, line));
	} else if (strcasecmp(command, "VRFY") == 0) {
		return (smtp_handle_vrfy(ta, line));
	} else {
		char *response = smtp_response(ta, errors);
		bufferevent_write(ta->bev, response, strlen(response));
	}

	return (0);
}

int
smtp_lock(const char *lockfile)
{
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP;
	int fd = open(lockfile, O_CREAT|O_RDWR, mode);
	if (fd == -1) {
		warn("%s: open(%s)", __func__, lockfile);
		return (-1);
	}

	if (flock(fd, LOCK_EX) == -1) {
		warn("%s: flock", __func__);
		close(fd);
		return (-1);
	}

	return (fd);
}

void
smtp_unlock(int fd)
{
	if (flock(fd, LOCK_UN) == -1)
		warn("%s: flock", __func__);
	close(fd);
}

int
smtp_chmkdir_one(const char *component)
{
	mode_t mode = S_IRUSR|S_IWUSR|S_IXUSR|S_IXGRP|S_IRGRP;

	struct stat sb;
	if (stat(component, &sb) == -1) {
		if (mkdir(component, mode) == -1) {
			warn("%s: %s: mkdir(%s)",
			    __func__,
			    getcwd(getcwdbuf, sizeof(getcwdbuf)), component);
			return (-1);
		}
	} else if ((sb.st_mode & S_IFDIR) == 0) {
		warnx("%s: something in the way of directory: %s.",
		    __func__, component);
		return (-1);
	}
	if (chdir(component) == -1) {
		warn("%s: %s: chdir(%s)",
		    __func__, getcwd(getcwdbuf, sizeof(getcwdbuf)), component);
		return (-1);
	}

	return (0);
}

int
smtp_chmkdir(const char *datadir, const char *address)
{
	char buf[32], *myaddress = buf, *p;

	strlcpy(buf, address, sizeof(buf));

	if (chdir(datadir) == -1) {
		warn("%s: chdir(%s)", __func__, datadir);
		return (-1);
	}

	while ((p = strsep(&myaddress, ".")) != NULL) {
		if (smtp_chmkdir_one(p) == -1)
			return (-1);
	}

	return (0);
}

/* Assumes a lock on the directory */

int
smtp_get_count(const char *countname)
{
	int fd = open(countname, O_RDONLY, 0);
	int count = -1;

	if (fd == -1) {
		if (errno == ENOENT)
			return (0);
		warn("%s: open(%s)", __func__, countname);
		return (-1);
	}

	if (atomicio(read, fd, &count, sizeof(count)) != count)
		goto out;

	/* We are good */

 out:
	close(fd);
	return (count);
}

int
smtp_write_count(const char *countname, int count)
{
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP;
	int fd = open(countname, O_CREAT|O_TRUNC|O_WRONLY, mode);

	if (fd == -1) {
		warn("%s: open(%s)", __func__, countname);
		return (-1);
	}

	if (atomicio(write, fd, &count, sizeof(count)) != count) {
		count = -1;
		goto out;
	}

	/* We are good */

 out:
	close(fd);
	return (count);
}

#define TOHEX(x) ((x) < 10 ? (x) + '0' : (x) - 10 + 'a')

char *
smtp_hashed_store(const char *datadir, void *data, size_t datalen)
{
	SHA1_CTX ctx;
	u_char digest[SHA1_DIGESTSIZE];
	static char adigest[2*SHA1_DIGESTSIZE+1];
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP;
	struct stat sb;
	int fd, i;

	SHA1Init(&ctx);
	SHA1Update(&ctx, data, datalen);
	SHA1Final(digest, &ctx);

	for (i = 0; i < sizeof(digest); ++i) {
		adigest[i*2] = TOHEX(digest[i] & 0xf);
		adigest[i*2 + 1] = TOHEX(digest[i] >> 4);
	}
	adigest[2*SHA1_DIGESTSIZE] = '\0';

	if (chdir(datadir) == -1) {
		warn("%s: chdir(%s)", __func__, datadir);
		return (adigest);
	}

	for (i = 0; i < 3; ++i) {
		char component[4];
		memcpy(component + 1, adigest + 2*i, 2);
		component[0] = '.';
		component[3] = '\0';
		if (smtp_chmkdir_one(component) == -1)
			return (adigest);
	}

	/* Somebody beat us to it */
	if (stat(adigest, &sb) != -1)
		return (adigest);

	if ((fd = open(adigest, O_CREAT|O_TRUNC|O_WRONLY, mode)) == -1) {
		warn("%s: open(%s)", __func__, adigest);
		return (adigest);
	}

	atomicio(write, fd, data, datalen);
	close(fd);

	return (adigest);
}

int
smtp_write_email(struct smtp_ta *ta, int count)
{
	struct evbuffer *buffer;
	char countname[10], *data;
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP;
	int fd;
	int res = -1;

	snprintf(countname, sizeof(countname), "%d", count);
	if ((fd = open(countname, O_CREAT|O_TRUNC|O_WRONLY, mode)) == -1) {
		warn("%s: open(%s)", __func__, countname);
		return (-1);
	}

	if ((buffer = evbuffer_new()) == NULL) {
		warn("%s: evbuffer_new", __func__);
		goto out;
	} else {
		char *hash;
		struct keyvalue *entry;
		char *srcname = kv_find(&ta->dictionary, "$srcname");
		char *sender = kv_find(&ta->dictionary, "$sender");

		evbuffer_add_printf(buffer, "srcname: %s\n", srcname);
		evbuffer_add_printf(buffer, "sender: %s\n", sender);

		TAILQ_FOREACH(entry, &ta->dictionary, next) {
			if (strcmp(entry->key, "$recipient"))
				continue;
			evbuffer_add_printf(buffer,
			    "recipient: %s\n", entry->value);
		}

		/* Find the headers and log them */
		while ((data = kv_find(&ta->dictionary, "data")) != NULL) {
			int done = 0;
			if (strlen(data)) 
				evbuffer_add_printf(buffer, "%s\n", data);
			else
				done = 1;
			kv_remove(&ta->dictionary, "data");
			if (done)
				break;
		}

		evbuffer_write(buffer, fd);

		/* 
		 * Log the rest of the data to the buffer, but we are going
		 * to treat it differently.
		 */
		while ((data = kv_find(&ta->dictionary, "data")) != NULL) {
			evbuffer_add_printf(buffer, "%s\n", data);
			kv_remove(&ta->dictionary, "data");
		}

		hash = smtp_hashed_store(log_datadir, 
		    EVBUFFER_DATA(buffer), EVBUFFER_LENGTH(buffer));
		evbuffer_drain(buffer, -1);

		evbuffer_add_printf(buffer, "\n%s\n", hash);
		evbuffer_write(buffer, fd);
	}

	res = 0;

 out:
	if (buffer != NULL)
		evbuffer_free(buffer);
	close(fd);
	return (res);
}

void
smtp_store(struct smtp_ta *ta, const char *dir)
{
	int lock_fd, count;
	char component[10];

	/* Do something here */
	char *srcip = kv_find(&ta->dictionary, "$srcipaddress");

	/* Create the directory we need. */
	if (smtp_chmkdir(log_datadir, srcip) == -1)
		return;

	if ((lock_fd = smtp_lock(LOCKNAME)) == -1)
		return;

	/* Do the maintenance while we are in the same directory */
	count = smtp_get_count(COUNTNAME);
	smtp_write_count(COUNTNAME, count + 1);

	snprintf(component, sizeof(component), "%d", count / 256);
	if (smtp_chmkdir_one(component) == -1)
		goto out;

	smtp_write_email(ta, count);

 out:
	smtp_unlock(lock_fd);
}

char *
smtp_readline(struct bufferevent *bev)
{
	struct evbuffer *buffer = EVBUFFER_INPUT(bev);
	char *data = EVBUFFER_DATA(buffer);
	size_t len = EVBUFFER_LENGTH(buffer);
	char *line;
	int i;

	for (i = 0; i < len; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}
	
	if (i == len)
		return (NULL);

	if ((line = malloc(i + 1)) == NULL) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		evbuffer_drain(buffer, i);
		return (NULL);
	}

	memcpy(line, data, i);
	line[i] = '\0';

	if ( i < len - 1 ) {
		char fch = data[i], sch = data[i+1];

		/* Drain one more character if needed */
		if ( (sch == '\r' || sch == '\n') && sch != fch )
			i += 1;
	}

	evbuffer_drain(buffer, i + 1);

	return (line);
}

void
smtp_readcb(struct bufferevent *bev, void *arg)
{
	char *line;

	while ((line = smtp_readline(bev)) != NULL) {
		struct smtp_ta *ta = arg;
		int res;

		res = smtp_handle(ta, line);
		
		DFPRINTF(1, (stderr, "%s: %s\n",
			     kv_find(&ta->dictionary, "$srcipaddress"),
			     line));

		free(line);

		/* Destroy the state machine on error */
		if (res == -1) {
			smtp_ta_free(ta);
			return;
		}
	}
}

void
smtp_writecb(struct bufferevent *bev, void *arg)
{
	struct smtp_ta *ta = arg;
	
	if (ta->wantclose)
		smtp_ta_free(ta);
}

void
smtp_errorcb(struct bufferevent *bev, short what, void *arg)
{
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	smtp_ta_free(arg);
}

/* Tear down a connection */
void
smtp_ta_free(struct smtp_ta *ta)
{
	struct keyvalue *entry;

	if (ta->dns_pending && !ta->dns_canceled) {
		/* if we have a pending dns lookup, tell it to cancel */
		ta->dns_canceled = 1;
		return;
	}

	while ((entry = TAILQ_FIRST(&ta->dictionary)) != NULL) {
		TAILQ_REMOVE(&ta->dictionary, entry, next);
		free(entry->key);
		free(entry->value);
		free(entry);
	}

	bufferevent_free(ta->bev);
	close(ta->fd);
	free(ta);
	
}

void
smtp_greeting(struct smtp_ta *ta)
{
	char *greeting;

	greeting = smtp_response(ta, welcome);
	if (greeting != NULL)
		bufferevent_write(ta->bev, greeting, strlen(greeting));
}

/* Create a new SMTP transaction */

struct smtp_ta *
smtp_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen, int greeting)
{
	struct smtp_ta *ta = calloc(1, sizeof(struct smtp_ta));
	char line[1024];
	char *ipname, *portname, *p;
	struct tm tm;
	time_t seconds;
	int i, seed;
	uint64_t hash;

	if (ta == NULL)
		goto error;

	TAILQ_INIT(&ta->dictionary);

	ta->state = EXPECT_HELO;
	ta->fd = fd;
	ta->bev = bufferevent_new(fd,
	    smtp_readcb, smtp_writecb, smtp_errorcb, ta);
	if (ta->bev == NULL)
		goto error;

	/* Create our tiny dictionary */
	name_from_addr(sa, salen, &ipname, &portname);
	kv_add(&ta->dictionary, "$srcipaddress", ipname);

	memcpy(&ta->sa, sa, salen);
	ta->salen = salen;

	/* Silly seed for domain name */
	hash = 0xdeadbeefL;
	p = (char *)&hash;
	for (i = 0; i < strlen(ipname); i++) {
		p[i % sizeof(hash)] ^= ipname[i];
	}
	hash = longhash1(hash);

	/* See if we know who we are, too */
	if (lsa != NULL) {
		memcpy(&ta->lsa, lsa, lsalen);
		ta->lsalen = lsalen;

		name_from_addr(lsa, lsalen, &ipname, &portname);
		kv_add(&ta->dictionary, "$dstipaddress", ipname);
		for (i = 0; i < strlen(ipname); i++) {
			p[i % sizeof(hash)] ^= ipname[i];
		}
	}

	seed = longhash1(hash);
	fprintf(stderr, "Seed: %s -> %x\n",
	    kv_find(&ta->dictionary, "$srcipaddress"), seed);
	srand(seed);

	seconds = time(NULL);
	localtime_r(&seconds, &tm);
	strftime(line, sizeof(line),
	    "%a, %e %b %Y %H:%M:%S %z (%Z)", &tm);
	kv_add(&ta->dictionary, "$datum", line);
	kv_add(&ta->dictionary, "$hostname", random_hostname());

	/* Choose a mailer identity */
	if (rand() % 2 == 0) {
		ta->mailer_id = "sendmail";
	} else {
		ta->mailer_id = "postfix";
	}

	if (greeting)
		smtp_greeting(ta);

	bufferevent_enable(ta->bev, EV_READ);

	fprintf(stderr, "%s: new SMTP instance to %s complete.\n",
	    __func__, kv_find(&ta->dictionary, "$srcipaddress"));

	srand(time(NULL) ^ seed);

	return (ta);

 error:
	if (ta != NULL)
		free(ta);
	fprintf(stderr, "%s: out of memory\n", __func__);
	close(fd);

	return (NULL);
}

void
accept_socket(int fd, short what, void *arg)
{
	struct sockaddr_storage ss, lss;
	socklen_t addrlen = sizeof(ss), laddrlen = sizeof(lss);
	int nfd, res;

	if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		fprintf(stderr, "%s: bad accept\n", __func__);
		return;
	}

	/* Test our special subsystem magic */
	res = fcntl(fd, F_XXX_GETSOCK, &lss, &laddrlen);

	if (res != -1) {
		/*
		 * We are running under honeyd and could figure out
		 * who we are.  That's great.
		 */
		smtp_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    (struct sockaddr *)&lss, laddrlen, 1);
	} else {
		smtp_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    NULL, 0, 1);
	}
}

void
smtp_bind_socket(struct event *ev, u_short port)
{
	int fd;

	if ((fd = make_socket(bind, SOCK_STREAM, "0.0.0.0", port)) == -1)
		err(1, "%s: cannot bind socket: %d", __func__, port);

	if (listen(fd, 10) == -1)
		err(1, "%s: listen failed: %d", __func__, port);

	/* Schedule the socket for accepting */
	event_set(ev, fd, EV_READ | EV_PERSIST, accept_socket, NULL);
	event_add(ev, NULL);

	fprintf(stderr, 
	    "Bound to port %d\n"
	    "Awaiting connections ... \n",
	    port);
}
