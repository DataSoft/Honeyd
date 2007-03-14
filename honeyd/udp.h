/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _UDP_H_
#define _UDP_H_

void udp_add_readbuf(struct udp_con *, u_char *, u_int);

void cmd_udp_eread(int, short, void *);
void cmd_udp_read(int, short, void *);
void cmd_udp_write(int, short, void *);
void cmd_udp_connect_cb(int, short, void *);

#endif
