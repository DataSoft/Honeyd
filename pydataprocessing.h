/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
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

#ifndef _PYDATAPROCESSING_
#define _PYDATAPROCESSING_

/* A function that takes input from the network and computes on it */
struct PyFilter {
	u_char digest[SHA1_DIGESTSIZE];		/* identifier of code */
	PyObject *compiled_code;		/* compiled Python code */
	PyObject *dict_local;			/* local dictionary */

	char *source_code;			/* available on original */
};

struct SingleValue {
	TAILQ_ENTRY(SingleValue) next;

	u_char *value;
	size_t vallen;
};

struct MergedKeyValue {
	SPLAY_ENTRY(MergedKeyValue) node;
	
	u_char *key;
	size_t keylen;

	TAILQ_HEAD(singlevalq, SingleValue) values;
	int num_values;
};

SPLAY_HEAD(mkvtree, MergedKeyValue);

struct PyMapFunction {
	TAILQ_ENTRY(PyMapFunction) next;
	
	struct PyFilter *local_map;
	struct PyFilter *local_reduce;

	char *destination_channel;
	
	struct mkvtree mkvs;
};

void pydataprocessing_init(void);

void pydataprocessing_test(void);

void PyFilterFree(struct PyFilter *filter);
struct PyFilter* PyFilterFromCode(char *code);

PyObject *PyFilterRun(struct PyFilter *filter, PyObject *record);

/*
 * Takes a tree of MergedKeyValue entries and integrates the results
 * from applying filter to it.
 */

int PyMapData(struct mkvtree *tree, struct PyFilter *filter, PyObject* input);

int PyMarshalToString(PyObject *pValue, char **data, int *datlen);


#endif /* _PYDATAPROCESSING_ */
