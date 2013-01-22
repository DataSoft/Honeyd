/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
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

#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <dnet.h>
#include <pcap.h>
#include <sha1.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include <Python.h>
#include <marshal.h>

#include "honeyd.h"
#include "tagging.h"
#include "untagging.h"
#include "stats.h"
#include "pydataprocessing.h"

/*
 * Data conversion functions use to interface Honeyd data with the
 * distributed data processing framework.
 */

/*
 * Creates a Python dictionary from a record object
 */

#define TV_TO_FLOAT(x) \
  ((float)(x)->tv_sec + (float)(x)->tv_usec / (float)1000000L)
	

PyObject* PyConvertRecord(struct record *record)
{
	PyObject *pValue = NULL;
	pValue = Py_BuildValue("{sfsfssssshshsbsbsisi}",
	    "tv_start", TV_TO_FLOAT(&record->tv_start),
	    "tv_end", TV_TO_FLOAT(&record->tv_end),
	    "src", addr_ntoa(&record->src),
	    "dst", addr_ntoa(&record->dst),
	    "src_port", record->src_port,
	    "dst_port", record->dst_port,
	    "proto", record->proto,
	    "state", record->state,
	    "bytes", record->bytes,
	    "flags", record->flags);

	if (pValue == NULL) {
		PyErr_Print();
		return (NULL);
	}

	if (record->os_fp != NULL) {
		PyObject *osfp = Py_BuildValue("s", record->os_fp);
		assert(osfp != NULL);
		if (PyDict_SetItemString(pValue, "os_fp", osfp) == -1) {
			Py_DECREF(osfp);
			Py_DECREF(pValue);
			return (NULL);
		}
		Py_DECREF(osfp);
	}

	if (TAILQ_FIRST(&record->hashes) != NULL) {
		struct hash *hash;
		PyObject* list = PyList_New(0);
		assert(list != NULL);

		TAILQ_FOREACH(hash, &record->hashes, next) {
			PyObject *digest;

			digest = Py_BuildValue("s#",
			    hash->digest, sizeof(hash->digest));
			assert(digest != NULL);
			if (PyList_Append(list, digest) == -1) {
				PyErr_Print();
				Py_DECREF(digest);
				Py_DECREF(list);
				Py_DECREF(pValue);
				return (NULL);
			}
			Py_DECREF(digest);
		}

		if (PyDict_SetItemString(pValue, "hashes", list) == -1) {
			Py_DECREF(list);
			Py_DECREF(pValue);
			return (NULL);
		}
		Py_DECREF(list);
	}

	return (pValue);
}

/***************************************************************************
 * Everything is unittest related below this
 ***************************************************************************/

static unsigned char record_data[] = {
0x03, 0x1e, 0x50, 0x00, 0x08, 0x76, 0x98, 0xcf,   0x03, 0x40, 0x42, 0xd4, 0x09, 0x02, 0x0d, 0x00,    // 0x0000  ..P..v.�  .@B�....
0x01, 0x02, 0x01, 0x02, 0x10, 0x20, 0x02, 0x04,   0x46, 0x1a, 0x69, 0xfe, 0x03, 0x0d, 0x00, 0x01,    // 0x0010  ..... ..  F.i�....
0x02, 0x01, 0x02, 0x10, 0x20, 0x02, 0x04, 0x0a,   0x00, 0x00, 0x5c, 0x04, 0x02, 0x2c, 0xfe, 0x05,    // 0x0020  .... ...  �S\..,�.
0x02, 0x28, 0x3c, 0x06, 0x01, 0x06, 0x07, 0x01,   0x01, 0x08, 0x0e, 0x57, 0x69, 0x6e, 0x64, 0x6f,    // 0x0030  .(<.....  ...Windo
0x77, 0x73, 0x20, 0x58, 0x50, 0x20, 0x53, 0x50,   0x31, 0x09, 0x08, 0xf0, 0xae, 0x58, 0x74, 0xa3,    // 0x0040  ws XP SP  1..�Xt�
0x87, 0x9f, 0x02, 0x09, 0x08, 0xb6, 0x50, 0xd6,   0x09, 0x2c, 0xcb, 0x15, 0x4f, 0x0a, 0x02, 0x22,    // 0x0050  .....�P�  .,�.O.."
0x21, 0x03, 0x1a, 0x30, 0x00, 0x08, 0x76, 0x98,   0xcf, 0x03, 0x40, 0x40, 0xf2, 0x8b, 0x02, 0x0d,    // 0x0060  !..0..v.  �.@@�...
0x00, 0x01, 0x02, 0x01, 0x02, 0x10, 0x20, 0x02,   0x04, 0x3d, 0x87, 0x84, 0x4c, 0x03, 0x0d, 0x00,    // 0x0070  ...... .  .=..L...
0x01, 0x02, 0x01, 0x02, 0x10, 0x20, 0x02, 0x04,   0x0a, 0x00, 0x00, 0xde, 0x04, 0x02, 0x1a, 0x50,    // 0x0080  ..... ..  .�S�...P
0x05, 0x03, 0x32, 0xa5, 0x70, 0x06, 0x01, 0x06,   0x07, 0x01, 0x01, 0x0b, 0x01, 0x01, 0x03, 0x1f,    // 0x0090  ..2�p...  ........
0x30, 0x00, 0x08, 0x76, 0x98, 0xcf, 0x03, 0x40,   0x43, 0x08, 0x2c, 0x02, 0x0d, 0x00, 0x01, 0x02,    // 0x00a0  0..v.�.@  C.,.....
0x01, 0x02, 0x10, 0x20, 0x02, 0x04, 0x0a, 0x00,   0x02, 0xb4, 0x03, 0x0d, 0x00, 0x01, 0x02, 0x01,    // 0x00b0  ... ...�  .�......
0x02, 0x10, 0x20, 0x02, 0x04, 0x0a, 0x00, 0x00,   0x6a, 0x04, 0x02, 0x15, 0x30, 0x05, 0x03, 0x37,    // 0x00c0  .. ...�S  j...0..7
0x72, 0x30, 0x06, 0x02, 0x11, 0x10, 0x07, 0x01,   0x01, 0x0a, 0x02, 0x1a, 0x80, 0x0b, 0x01, 0x01,    // 0x00d0  r0......  ........
};

void
pyrecord_test(void)
{
	char *some_code =
	    "def TestProcessing(input):\n"
	    "  print '\t\t', input\n"
	    "  return [ [ input['src'], '\x01' ] ]\n"
	    "output_record = TestProcessing(input_record)\n";

	PyObject *pValue, *pRes;
	struct PyFilter *filter = PyFilterFromCode(some_code);
	char *result;
	int res_len;
	struct record *record = NULL;
	struct evbuffer *tmp = evbuffer_new();
	assert(filter != NULL);
	assert(tmp != NULL);

	evbuffer_add(tmp, record_data, sizeof(record_data));
	while (evbuffer_get_length(tmp)) {
		if ((record = calloc(1, sizeof(struct record))) == NULL)
		{
			syslog(LOG_ERR, "%s: calloc", __func__);
			exit(EXIT_FAILURE);
		}

		assert(tag_unmarshal_record(tmp, M_RECORD, record) != -1);

		pValue = PyConvertRecord(record);

		if (pValue == NULL) {
			PyErr_Print();
			syslog(LOG_ERR,"%s: failed to convert record", __func__);
			exit(EXIT_FAILURE);
		}

		pRes = PyFilterRun(filter, pValue);
		if (pRes == NULL) {
			PyErr_Print();
			exit(EXIT_FAILURE);
		}

		if (PyMarshalToString(pRes, &result, &res_len) == -1) {
			PyErr_Print();
			exit(EXIT_FAILURE);
		}

		Py_DECREF(pRes);
		Py_DECREF(pValue);
	
		fprintf(stderr, "\t\tResult len: %d\n", res_len);
	
		free(record);
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
pydatahoneyd_test(void)
{
	if (!Py_IsInitialized())
		Py_Initialize();

	pyrecord_test();
}
