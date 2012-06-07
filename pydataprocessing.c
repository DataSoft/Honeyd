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

#include "pydataprocessing.h"

int
mkv_compare(struct MergedKeyValue *a, struct MergedKeyValue *b)
{
	if (a->keylen < b->keylen)
		return (-1);
	if (a->keylen > b->keylen)
		return (1);
	return (memcmp(a->key, b->key, a->keylen));
}

SPLAY_PROTOTYPE(mkvtree, MergedKeyValue, node, mkv_compare);
SPLAY_GENERATE(mkvtree, MergedKeyValue, node, mkv_compare);

struct MergedKeyValue *
MergedKeyValueNew(struct mkvtree *tree, u_char *key, size_t keylen)
{
	struct MergedKeyValue *mkv, tmp;

	tmp.key = key;
	tmp.keylen = keylen;
	if (SPLAY_FIND(mkvtree, tree, &tmp) != NULL)
		return (NULL);
	    
	mkv = calloc(1, sizeof(struct MergedKeyValue));
	if (mkv == NULL) {
		warn("%s: calloc");
		return (NULL);
	}

	mkv->keylen = keylen;
	if ((mkv->key = malloc(keylen)) == NULL) {
		warn("%s: malloc");
		free(mkv);
		return (NULL);
	}
	memcpy(mkv->key, key, keylen);
	
	TAILQ_INIT(&mkv->values);

	SPLAY_INSERT(mkvtree, tree, mkv);

	return (mkv);
}

void
MergedKeyValueFree(struct mkvtree *tree, struct MergedKeyValue *mkv)
{
	struct SingleValue *sv;
	SPLAY_REMOVE(mkvtree, tree, mkv);

	while ((sv = TAILQ_FIRST(&mkv->values)) != NULL) {
		TAILQ_REMOVE(&mkv->values, sv, next);
		free(sv->value);
		free(sv);
	}

	free(mkv->key);
	free(mkv);
}

int
MergedKeyValueInsert(struct mkvtree *tree,
    u_char *key, size_t keylen, u_char *value, size_t vallen)
{
	struct MergedKeyValue *mkv, tmp;
	struct SingleValue *sv;
	
	tmp.key = key;
	tmp.keylen = keylen;

	mkv = SPLAY_FIND(mkvtree, tree, &tmp);
	if (mkv == NULL) {
		mkv = MergedKeyValueNew(tree, key, keylen);
		if (mkv == NULL)
			return (-1);
	}

	if ((sv = calloc(1, sizeof(struct SingleValue))) == NULL) {
		warn("%s: calloc");
		return (-1);
	}

	if ((sv->value = malloc(vallen)) == NULL) {
		warn("%s: malloc");
		free(sv);
		return (-1);
	}

	sv->vallen = vallen;
	memcpy(sv->value, value, vallen);

	TAILQ_INSERT_TAIL(&mkv->values, sv, next);
	mkv->num_values++;

	return (0);
}

int
PyMapData(struct mkvtree *tree, struct PyFilter *filter, PyObject* input)
{
	PyObject* output = PyFilterRun(filter, input);
	char *dat_key = NULL, *dat_value = NULL;
	int dat_keylen = 0, dat_vallen = 0;
	int i = 0;
	int res = -1;
	
	if (output == NULL)
		return (-1);

	if (!PyList_Check(output)) {
		warnx("%s: map returned a non-list object", __func__);
		goto out;
	}

	for (i = 0; i < PyList_Size(output); ++i) {
		PyObject *item = PyList_GetItem(output, i);
		PyObject *key, *value;
		
		assert(item != NULL);

		if (!PyList_Check(item)) {
			warnx("%s: list item %d is a non-list object",
			    __func__, i);
			goto out;
		}

		if (PyList_Size(item) != 2) {
			warnx("%s: internal list is not of correct size.",
			    __func__);
			goto out;
		}

		key = PyList_GetItem(item, 0);
		if (key == NULL || !PyString_Check(key)) {
			warnx("%s: key not available or not string", __func__);
			goto out;
		}
		value = PyList_GetItem(item, 1);
		if (value == NULL || !PyString_Check(value)){
			warnx("%s: value not available or not string",
			    __func__);
			goto out;
		}

		if (PyString_AsStringAndSize(key, &dat_key, &dat_keylen) == -1){
			PyErr_Print();
			goto out;
		}
		if (PyString_AsStringAndSize(value,
			&dat_value, &dat_vallen) == -1) {
			PyErr_Print();
			goto out;
		}

		/* Merge the returned key and value with existing keys */
		MergedKeyValueInsert(tree,
		    dat_key, dat_keylen, dat_value, dat_vallen);
	}

	/* Everything was well */
	res = 0;
 out:
	Py_DECREF(output);
	return (res);
}

void
pydataprocessing_init(void)
{
}

void
PyFilterFree(struct PyFilter *filter)
{
	if (filter->compiled_code != NULL) {
		    Py_DECREF(filter->compiled_code);
		    filter->compiled_code = NULL;
	}


	if (filter->source_code != NULL) {
		free(filter->source_code);
		filter->source_code = NULL;
	}

	if (filter->dict_local != NULL) {
		Py_DECREF(filter->dict_local);
		filter->dict_local = NULL;
	}

	free(filter);
}

struct PyFilter*
PyFilterFromCode(char *code)
{
	struct PyFilter *filter = calloc(1, sizeof(struct PyFilter));
	if (filter == NULL) {
		warn("%s: calloc", __func__);
		return (NULL);
	}

	filter->compiled_code =
	    Py_CompileStringFlags(code, "<filter>", Py_file_input, 0);
	if (filter->compiled_code == NULL) {
		PyErr_Print();
		goto error;
	}

	filter->source_code = strdup(code);
	if (filter->source_code == NULL) {
		warn("%s: stdrup", __func__);
		goto error;
	}

	if ((filter->dict_local = PyDict_New()) == NULL)
		goto error;
	
	return (filter);

 error:
	PyFilterFree(filter);
	return (NULL);
}

PyObject *
PyUnmarshalString(char *input, size_t len)
{
	PyObject *record = PyMarshal_ReadObjectFromString(input, len);
	if (record == NULL)
		PyErr_Print();

	return (record);
}

int
PyMarshalToString(PyObject *pValue, char **data, int *datlen)
{
	int res = -1;
	PyObject *datastr = NULL;
	datastr = PyMarshal_WriteObjectToString(pValue, Py_MARSHAL_VERSION);
	if (datastr == NULL)
		return (-1);
	res = PyString_AsStringAndSize(datastr, data, datlen);
	Py_DECREF(datastr);

	return (res);
}

PyObject *
PyFilterRun(struct PyFilter *filter, PyObject *record)
{
	extern PyObject *pyextend_dict_global;
	PyObject *res;

	if (pyextend_dict_global == NULL) {
		PyObject *m;

		/* Extract the global dictionary object */
		if ((m = PyImport_AddModule("__main__")) == NULL) {
			PyErr_Print();
			return (NULL);
		}

		if ((pyextend_dict_global = PyModule_GetDict(m)) == NULL) {
			PyErr_Print();
			return (NULL);
		}
		Py_INCREF(pyextend_dict_global);

		if (PyDict_GetItemString(pyextend_dict_global,
			"__builtins__") == NULL &&
		    PyDict_SetItemString(pyextend_dict_global,
			"__builtins__", PyEval_GetBuiltins()) == 0) {
			Py_DECREF(pyextend_dict_global);
			pyextend_dict_global = NULL;
			return (NULL);
		}
	}

	PyDict_SetItemString(filter->dict_local, "input_record", record);
	if (PyErr_Occurred())
		return (NULL);

	res = PyEval_EvalCode((PyCodeObject *)filter->compiled_code,
	    pyextend_dict_global, filter->dict_local);
	if (res == NULL)
		return (NULL);
	Py_DECREF(res);

	/* Retrieve variable value */
	res = PyDict_GetItemString(filter->dict_local, "output_record");
	if (res != NULL)
		Py_INCREF(res);

	return (res);
}

/***************************************************************************
 * Everything is unittest related below this
 ***************************************************************************/

void
pyfilter_test(void)
{
	char *some_code =
	    "def TestProcessing(input):\n"
	    "  print '\t\tinput: %d' % len(input)\n"
	    "  return [ [ input['src'], '\x01' ], [ input['dst'], '\x01' ] ]\n"
	    "output_record = TestProcessing(input_record)\n";

	PyObject *pValue, *pRes;
	struct PyFilter *filter = PyFilterFromCode(some_code);
	struct mkvtree mkvs;
	char *result;
	int res_len;
	assert(filter != NULL);

	SPLAY_INIT(&mkvs);
	
	pValue = Py_BuildValue("{sssssisisisi}",
	    "src", "127.0.0.1",
	    "dst", "127.0.0.2",
	    "sport", 50,
	    "dport", 51,
	    "received", 1024,
	    "sent", 512);

	if (pValue == NULL) {
		PyErr_Print();
		errx(1, "%s: failed to build argument list", __func__);
	}

	pRes = PyFilterRun(filter, pValue);
	if (pRes == NULL) {
		PyErr_Print();
		assert(pRes != NULL);
	}

	assert(PyMarshalToString(pRes, &result, &res_len) != -1);

	Py_DECREF(pRes);
	
	fprintf(stderr, "\t\tResult len: %d\n", res_len);
	
	assert(PyMapData(&mkvs, filter, pValue) != -1);

	Py_DECREF(pValue);
	
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
pydataprocessing_test(void)
{
	Py_Initialize();

	pyfilter_test();
}
