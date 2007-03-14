/* This header file is in the public domain */
#ifndef _DNET_H_
#define _DNET_H_

/* This header file takes care of hiding the variations in
 * libdnet names -- in particular, libdnet is libdumbnet
 * on Debian, and dnet-config doesn't hide this :( --CPK.
 */
#ifdef HAVE_DUMBNET
#include <dumbnet.h>
#endif

#endif
