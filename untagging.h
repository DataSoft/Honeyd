/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifndef _UNTAGGING_
#define _UNTAGGING_

void tagging_test(void);

int record_unmarshal(struct record *, struct evbuffer *);

int addr_unmarshal(struct addr *, struct evbuffer *);

/* 
 * Marshaling tagged data - We assume that all tags are inserted in their
 * numeric order - so that unknown tags will always be higher than the
 * known ones - and we can just ignore the end of an event buffer.
 */

int tag_unmarshal(struct evbuffer *src, uint8_t *ptag, struct evbuffer *dst);
int tag_peek(struct evbuffer *evbuf, uint8_t *ptag);
int tag_peek_length(struct evbuffer *evbuf, uint32_t *plength);
int tag_consume(struct evbuffer *evbuf);

int decode_int(uint32_t *pnumber, struct evbuffer *evbuf);

int tag_unmarshal_int(struct evbuffer *evbuf, uint8_t need_tag,
    uint32_t *pinteger);

int tag_unmarshal_fixed(struct evbuffer *src, uint8_t need_tag, void *data,
    size_t len);

int tag_unmarshal_string(struct evbuffer *evbuf, uint8_t need_tag,
    char **pstring);

int tag_unmarshal_timeval(struct evbuffer *evbuf, uint8_t need_tag,
    struct timeval *ptv);

int tag_unmarshal_record(struct evbuffer *evbuf, uint8_t need_tag,
    struct record *record);

#endif /* _UNTAGGING_ */
