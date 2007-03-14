/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
/*
 * Copyright 2003 Christopher Kolina, Derek Cotton and Yuqing Mai
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dnet.h>
#include <ctype.h>

#undef timeout_pending
#undef timeout_initialized

#include <math.h>
#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "xprobe_assoc.h"

static int
assoc_compare(assoc_item *a, assoc_item *b)
{
  return strcmp(a->nmap_name, b->nmap_name);
}

SPLAY_HEAD(assoc_tree, assoc_item) associations;
SPLAY_PROTOTYPE(assoc_tree, assoc_item, node, assoc_compare);

SPLAY_GENERATE(assoc_tree, assoc_item, node, assoc_compare);

void
associations_init(void)
{
	SPLAY_INIT(&associations);
}

/**
 * Retrieves a single line from the associations files and parses it.
 *
 * @param fp the FILE stream pointer
 * @return NULL if the line did not parse to an association, or a new
 *         assoc_item if it did.
 */

static assoc_item *
get_assoc(FILE *fp)
{
	char line[1024];
	char *p, *q;
	assoc_item *assoc = NULL;
	struct xp_fingerprint fprint;

	/* Get one line */
	p = fgets(line, sizeof(line), fp);
	if (p == NULL)
		return (NULL);

	/* Remove leading whitespace */
	p += strspn(p, WHITESPACE);

	/* Remove comments and blank lines */
	if (*p == '\0' || *p == '#')
		return (NULL);

	/* Remove trailing comments */
	q = p;
	strsep(&q, "#\r\n");

	/* Split on ; */
	q = p;
	p = strsep(&q, ";");
	if (p == NULL || q == NULL)
		return (NULL);

	/* Make a new association */
	assoc = (assoc_item *)calloc(1, sizeof(struct assoc_item));
	if (assoc == NULL)
		return (NULL);

	/* The value in p is the nmap name.  The value in q is the xprobe
	 * name.
	 */
	fprint.os_id = q;
	assoc->nmap_name = strdup(p);
	assoc->xp_fprint = SPLAY_FIND(xp_fprint_tree, &xp_fprints, &fprint);

	/* Make sure the strdup and SPLAY_FIND succeeded, otherwise clean up */
	if (assoc->nmap_name == NULL || assoc->xp_fprint == NULL) {
		if (assoc->nmap_name)
			free (assoc->nmap_name);
		free (assoc);
		return (NULL);
	}

	/* fprintf(stderr, "%s <-> %s\n",p,q); */
	return (assoc);
}

/**
 * Loads associations by getting one association at a time, then adding it
 * to the associations splay tree.
 *
 * @param fp the FILE stream pointer
 * @return -1 on error, 0 on success
 */

int
parse_associations(FILE *fp)
{
	assoc_item *assoc = NULL;

	if (fp == NULL) {
		fprintf(stderr, "Could not open associations file!\n");
		return (-1);
	}

	while (!feof(fp)) {
		assoc = get_assoc(fp);
		if (assoc != NULL)
			SPLAY_INSERT(assoc_tree, &associations, assoc);
	}

	return (0);
}

/**
 * Takes a personality that is filled with NMAP personality information and
 * adds the corresponding Xprobe OS (if possible) to the personality by looking
 * up the NMAP OS name in the associations splay tree.
 *
 * @param pers The pre-filled NMAP personality to look up in the association tree
 * @return 0 if no matching association was found, or 1 if one was
 */

int
correlate_nmap_with_xprobe(struct personality *pers)
{
	struct assoc_item *assoc;
	struct assoc_item lookup;

	if (pers == NULL)
		return 0;

	/* Lookup the association */
	lookup.nmap_name = pers->name;
	if ((assoc = SPLAY_FIND(assoc_tree, &associations, &lookup)) == NULL)
		return (0);

	/* 
	 * If we have the association, put the xprobe fingerprint in
	 * the personality.
	 */
	pers->xp_fprint = assoc->xp_fprint;

	return (0);
}
