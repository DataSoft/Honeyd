/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _PARSER_H_
#define _PARSER_H_

struct evbuffer;
int parse_configuration(FILE *, char *);
int parse_line(struct evbuffer *, char *);

#endif /* !_PARSER_H_ */
