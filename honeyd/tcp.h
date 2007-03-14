/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
#ifndef _TCP_H_
#define _TCP_H_

int tcp_add_readbuf(struct tcp_con *, u_char *, u_int);
void tcp_drain_payload(struct tcp_con *, u_int);
void tcp_increase_buf(u_char **, u_int *, u_int);

void cmd_tcp_eread(int, short, void *);
void cmd_tcp_read(int, short, void *);
void cmd_tcp_write(int, short, void *);
void cmd_tcp_connect_cb(int, short, void *);

#endif
