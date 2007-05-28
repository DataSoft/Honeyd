/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * Copyright 2003 Christian Kreibich <christian.kreibich@cl.cam.ac.uk>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <dnet.h>

#include "hooks.h"

#define HD_HOOKS_TCP        0
#define HD_HOOKS_UDP        1
#define HD_HOOKS_ICMP       2
#define HD_HOOKS_OTHER      3
#define HD_HOOKS_LAST       4

/* Packet hooks are simply and only consist of a
 * callback and pointers so that we can register them
 * in tail queues.
 */
struct honeyd_packet_hook
{
	TAILQ_ENTRY(honeyd_packet_hook) next;

	HD_PacketCallback               callback;
	void                           *user_data;
};

TAILQ_HEAD(hooksq, honeyd_packet_hook);

/*
 * Arrays of hook tailqueues, each with HD_HOOKS_LAST elements,
 * indexed using the HD_HOOKS_xxx constants:
 */
struct hooksq  *dir_hooks[HD_DIR_MAX];

void    
hooks_init(void)
{
	int i, j;

	for (i = 0; i < HD_DIR_MAX; i++) {
		dir_hooks[i] = malloc(HD_HOOKS_LAST * sizeof(struct hooksq));
		if (dir_hooks[i] == NULL)
			err(1, "%s: malloc", __func__);
	}

	for (i = 0; i < HD_HOOKS_LAST; i++)
		for (j = 0; j < HD_DIR_MAX; j++)
			TAILQ_INIT(&dir_hooks[j][i]);
}

void    
hooks_add_packet_hook(int protocol, HD_Direction dir,
		      HD_PacketCallback callback,
		      void *user_data)
{
	struct hooksq *hooks;
	struct honeyd_packet_hook *hook;
	
	if (!callback)
		return;
	
	if ( (hook = calloc(1, sizeof(struct honeyd_packet_hook))) == NULL)
		return;
	
	hook->callback  = callback;
	hook->user_data = user_data;

	hooks = dir_hooks[dir];

	switch (protocol) {
	case IP_PROTO_TCP:
		TAILQ_INSERT_HEAD(&hooks[HD_HOOKS_TCP], hook, next);
		break;
		
	case IP_PROTO_UDP:
		TAILQ_INSERT_HEAD(&hooks[HD_HOOKS_UDP], hook, next);
		break;

	case IP_PROTO_ICMP:
		TAILQ_INSERT_HEAD(&hooks[HD_HOOKS_ICMP], hook, next);
		break;
		
	default:
		TAILQ_INSERT_HEAD(&hooks[HD_HOOKS_OTHER], hook, next);
	}  
}


static void
hooks_remove_impl(struct hooksq *hooks, HD_PacketCallback callback)
{
	struct honeyd_packet_hook *hook, *next;
	
	for (hook = TAILQ_FIRST(hooks); hook; hook = next) {
		next = TAILQ_NEXT(hook, next);
		
		if (hook->callback == callback)
			TAILQ_REMOVE(hooks, hook, next);
	}
}


void    
hooks_remove_packet_hook(int protocol, HD_Direction dir,
    HD_PacketCallback callback)
{
	struct hooksq *hooks;

	if (callback == NULL)
		return;
	
	hooks = dir_hooks[dir];

	switch (protocol) {
	case IP_PROTO_TCP:
		hooks_remove_impl(&hooks[HD_HOOKS_TCP], callback);
		break;
		
	case IP_PROTO_UDP:
		hooks_remove_impl(&hooks[HD_HOOKS_UDP], callback);
		break;

	case IP_PROTO_ICMP:
		hooks_remove_impl(&hooks[HD_HOOKS_ICMP], callback);
		break;
		
	default:
		hooks_remove_impl(&hooks[HD_HOOKS_OTHER], callback);
	}  
}


void    
hooks_dispatch(int protocol, HD_Direction dir, struct tuple *conhdr,
    u_char *packet_data, u_int packet_len)
{
	struct hooksq *hooks;
	struct honeyd_packet_hook *hook;
	
	if (packet_data == NULL)
		return;
	
	hooks = dir_hooks[dir];

	switch (protocol) {
	case IP_PROTO_TCP:
		TAILQ_FOREACH(hook, &hooks[HD_HOOKS_TCP], next)
		    hook->callback(conhdr, packet_data, packet_len,
			hook->user_data);
		break;
		
	case IP_PROTO_UDP:
		TAILQ_FOREACH(hook, &hooks[HD_HOOKS_UDP], next)
		    hook->callback(conhdr, packet_data, packet_len,
			hook->user_data);
		break;
		
	case IP_PROTO_ICMP:
		TAILQ_FOREACH(hook, &hooks[HD_HOOKS_ICMP], next)
		    hook->callback(conhdr, packet_data, packet_len,
			hook->user_data);
		break;
		
	default:
		TAILQ_FOREACH(hook, &hooks[HD_HOOKS_OTHER], next)
		    hook->callback(conhdr, packet_data, packet_len,
			hook->user_data);
	}  
}
