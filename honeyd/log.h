/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _LOG_
#define _LOG_

FILE *honeyd_logstart(const char *);
void honeyd_logend(FILE *);
void honeyd_log_probe(FILE *, int, const struct tuple *, int, int,
    const char *);
void honeyd_log_flownew(FILE *, int, const struct tuple *);
void honeyd_log_flowend(FILE *, int, const struct tuple *);
void honeyd_log_service(FILE *, int, const struct tuple *, const char *);
char *honeyd_logdate(void);

#endif /* _LOG_ */
