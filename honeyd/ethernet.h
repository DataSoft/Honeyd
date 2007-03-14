/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _ETHERNET_
#define _ETHERNET_

void ethernetcode_init(void);
uint32_t ethernetcode_find_prefix(char *, int);
struct addr *ethernetcode_make_address(char *);
struct addr *ethernetcode_clone(struct addr *);

void ethernet_test(void);

#endif /* _ETHERNET_ */
