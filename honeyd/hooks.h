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
#ifndef _HOOKS_H_
#define _HOOKS_H_

typedef enum {
	HD_INCOMING,
	HD_OUTGOING,
	HD_INCOMING_STREAM,	/* just the payload that is actually new */
	HD_DIR_MAX
} HD_Direction;


/**
 * HD_PacketCallback - hook implementation signature.
 * @packet_data: raw packet data.
 * @packet_len: length of data.
 * @user_data: arbitrary user data.
 *
 * This is the signature for packet hook callbacks. Users can register
 * functions of this signature to be called when packets containing certain
 * protocol headers are received or sent. The packet data is then passed
 * in via @packet_data. @user_data contains the value specified when
 * the callback got registered using hooks_add_packet_hook().
 */
struct tuple;
typedef void (*HD_PacketCallback) (struct tuple *conhdr,
    u_char *packet_data, u_int packet_len, void *user_data);


/**
 * hooks_init - hook system initializer.
 *
 * The function initializes the data structures that manage the hooks.
 */
void    hooks_init(void);


/**
 * hooks_add_packet_hook - adds a callback for a particular protocol.
 * @protocol: number of protocol, a %IP_PROTO_xxx value.
 * @dir: whether the hook is for incoming or outgoing packets.
 * @callback: callback used when a packet of type @protocol is encountered.
 * @user_data: arbitrary data to pass to the callback.
 *
 * The function registers @callback to be called whenever packets of type
 * @protocol are encountered.
 */
void    hooks_add_packet_hook(int protocol, HD_Direction dir,
			      HD_PacketCallback callback,
			      void *user_data);


/**
 * hooks_remove_packet_hook - removes a callback.
 * @protocol: number of protocol, a %IP_PROTO_xxx value.
 * @dir: whether the hook for incoming or outgoing packets is to be removed.
 * @callback: callback to remove.
 *
 * The function removes @callback from the list of registered callbacks for
 * packets of type @protocol.
 */
void    hooks_remove_packet_hook(int protocol, HD_Direction dir, HD_PacketCallback callback);


/**
 * hooks_dispatch - callback dispatcher.
 * @protocol: number of protocol, a %IP_PROTO_xxx value.
 * @dir: incoming or outcoming.
 * @packet_data: packet to dispatch to callbacks.
 * @packet_len: length of packet data.
 *
 * The function calls all the registered callbacks for protocol type
 * @protocol, passing them the given @packet_data.
 */
void    hooks_dispatch(int protocol, HD_Direction dir, struct tuple *conhdr,
		       u_char *packet_data, u_int packet_len);

#endif

