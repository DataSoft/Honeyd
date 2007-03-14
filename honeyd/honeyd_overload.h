/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */

#ifndef _HONEYD_OVERLOAD_H_
#define _HONEYD_OVERLOAD_H_

struct bundle {
	struct sockaddr_in src;
	struct sockaddr_in dst;
};

/*
 * Should be called directly after accept on the accept fd.  this will return
 * the sockaddr_in of the destination address for this ip address. very
 * helpful when sharing subsystems.
 */
#define F_XXX_GETSOCK	0xdead

#endif /* _HONEYD_OVERLOAD_H_ */
