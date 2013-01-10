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

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include <Python.h>

#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "interface.h"
#include "log.h"
#include "pyextend.h"
#include "histogram.h"
#include "osfp.h"
#include "debug.h"

int make_socket(int (*f)(int, const struct sockaddr *, socklen_t), int type,
    char *, uint16_t);

/*
 * Can be used externally to share Python dictionaries with the user interface
 */
PyObject *pyextend_dict_global;
PyObject *pyextend_dict_local;

/* 
 * Functions that we need to call for this script.
 * This is stateless and shared among connections.
 */

struct pyextend {
	SPLAY_ENTRY(pyextend) node;
	char *name;
	PyObject *pFuncInit;
	PyObject *pFuncReadData;
	PyObject *pFuncWriteData;
	PyObject *pFuncEnd;
};

SPLAY_HEAD(pyetree, pyextend) pyextends;

int
pye_compare(struct pyextend *a, struct pyextend *b)
{
	return (strcmp(a->name, b->name));
}

SPLAY_PROTOTYPE(pyetree, pyextend, node, pye_compare);
SPLAY_GENERATE(pyetree, pyextend, node, pye_compare);

struct pywrite {
	TAILQ_ENTRY(pywrite) next;

	u_char *buf;
	size_t size;
};

struct pystate {
	PyObject *state;

	struct pyextend *pye;

	int fd;

	struct event pread;
	struct event pwrite;
	
	int wantwrite;

	TAILQ_HEAD(pywbufs, pywrite) writebuffers;

	struct command *cmd;
	void *con;
};

static PyObject *pyextend_readselector(PyObject *, PyObject *);
static PyObject *pyextend_writeselector(PyObject *, PyObject *);
static PyObject *pyextend_log(PyObject *, PyObject *);
static PyObject *pyextend_raw_log(PyObject *, PyObject *);
static PyObject *pyextend_uptime(PyObject *, PyObject *);
static PyObject *pyextend_interfaces(PyObject *, PyObject *);
static PyObject *pyextend_stats_network(PyObject *, PyObject *);
static PyObject *pyextend_status_connections(PyObject *, PyObject *);
static PyObject *pyextend_config(PyObject *, PyObject *);
static PyObject *pyextend_config_ips(PyObject *, PyObject *);
static PyObject *pyextend_delete_template(PyObject *, PyObject *);
static PyObject *pyextend_delete_connection(PyObject *, PyObject *);

static PyMethodDef HoneydMethods[] = {
    {"read_selector", pyextend_readselector, METH_VARARGS,
     "Tells Honeyd if the embedded Python application wants to read or not."},
    {"write_selector", pyextend_writeselector, METH_VARARGS,
     "Tells Honeyd if the embedded Python application wants to write or not."},
    {"log", pyextend_log, METH_VARARGS,
     "Allows a python script to pass a string to generate service logs."},
    {"raw_log", pyextend_raw_log, METH_VARARGS,
     "Allows a python script to log directly to syslog."},
    {"uptime", pyextend_uptime, METH_VARARGS,
     "Returns the number of seconds that Honeyd has been running."},
    {"interfaces", pyextend_interfaces, METH_VARARGS,
     "Returns an array of configured interfaces."},
    {"stats_network", pyextend_stats_network, METH_VARARGS,
     "Returns a dictionary with network statistics."},
    {"status_connections", pyextend_status_connections, METH_VARARGS,
     "Returns a list of active UDP or TCP connections."},
    {"config", pyextend_config, METH_VARARGS,
     "Returns an associative array with config information."},
    {"config_ips", pyextend_config_ips, METH_VARARGS,
     "Returns an array with bound IP addresses."},
    {"delete_template", pyextend_delete_template, METH_VARARGS,
     "Deletes the specified template."},
    {"delete_connection", pyextend_delete_connection, METH_VARARGS,
     "Deletes the specified connection."},
    {NULL, NULL, 0, NULL}
};

static struct pystate *current_state;

struct pyextend_count {
	int offset;
	PyObject *pArgs;
};

static int
pyextend_populate_connections(struct tuple *hdr, void *arg)
{
	PyObject *pArgs = arg, *pValue;
	struct addr src, dst;
	
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);

	pValue = Py_BuildValue("{sssssisisisi}",
	    "src", addr_ntoa(&src),
	    "dst", addr_ntoa(&dst),
	    "sport", hdr->sport,
	    "dport", hdr->dport,
	    "received", hdr->received,
	    "sent", hdr->sent);
	if (pValue == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: failed to build argument list", __func__);
		exit(EXIT_FAILURE);
	}

	/* pValue reference stolen here */
	PyList_Append(pArgs, pValue);

	return (0);
}

static PyObject*
pyextend_status_connections(PyObject *self, PyObject *args)
{
	PyObject *pArgs;
	char *string;
	extern struct conlru tcplru;
	extern struct conlru udplru;
	struct conlru *head;

	if (!PyArg_ParseTuple(args, "s", &string))
		return NULL;

	/* Check that we are asking for either UDP or TCP */
	if (!strcmp(string, "udp"))
		head = &udplru;
	else if (!strcmp(string, "tcp"))
		head = &tcplru;
	else
		return NULL;

	pArgs = PyList_New(0);

	/* Populate tuple with per IP address information */
	tuple_iterate(head, pyextend_populate_connections, pArgs);

	return (pArgs);
}

/*
 * Returns 1 if the template name corresponds to an IP address
 */

int
pyextend_is_ipaddress(struct template *tmpl)
{
	ip_addr_t addr;

	return (ip_pton(tmpl->name, &addr) != -1);
}

int
pyextend_count_ips(struct template *tmpl, void *arg)
{
	int *num_ips = arg;

	if (!pyextend_is_ipaddress(tmpl))
		return (0);

	(*num_ips)++;

	return (0);
}

void
pyextend_humanreadable_action(struct action *action, char *buffer, size_t len)
{
	char *flags = NULL;
	if (action->flags & PORT_TARPIT) {
		flags = "tarpit ";
	}

	switch (action->status) {
	case PORT_FILTERED:
		snprintf(buffer, len, "filtered");
		break;

	case PORT_CLOSED:
		snprintf(buffer, len, "closed");
		break;

	case PORT_OPEN:
		snprintf(buffer, len, "%s%s",
		    flags != NULL ? flags : "",
		    action->action != NULL ? action->action : "open");
		break;
	case PORT_PYTHON:
		snprintf(buffer, len, "%sinternal %s",
		    flags != NULL ? flags : "",
		    action->action);
		break;
	case PORT_PROXY:
		if (action->action != NULL) {
			snprintf(buffer, len, "%sproxy %s",
			    flags != NULL ? flags : "",
			    action->action);
		} else if (action->aitop != NULL) {
			struct addrinfo *ai = action->aitop;
			char addr[NI_MAXHOST];
			char port[NI_MAXSERV];

			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
				addr, sizeof(addr), port, sizeof(port),
				NI_NUMERICHOST|NI_NUMERICSERV) != 0)
			{
				syslog(LOG_ERR, "%s: getnameinfo", __func__);
				exit(EXIT_FAILURE);
			}
			snprintf(buffer, len, "%sproxy %s:%s",
			    flags != NULL ? flags : "",
			    addr, port);
		} else {
			snprintf(buffer, len, "proxy UNKNOWN");
		}
		break;
	default:
		snprintf(buffer, len, "UNKNOWN");
		break;
	}
}

int
pyextend_populate_ips(struct template *tmpl, void *arg)
{
	struct pyextend_count *count = arg;
	char icmp_action[1024];
	char tcp_action[1024];
	char udp_action[1024];
	PyObject *pArgs = count->pArgs;
	PyObject *pValue;

	if (!pyextend_is_ipaddress(tmpl))
		return (0);

	/* Fill in the default actions that we take */
	pyextend_humanreadable_action(&tmpl->icmp,
	    icmp_action, sizeof(icmp_action));
	pyextend_humanreadable_action(&tmpl->tcp,
	    tcp_action, sizeof(tcp_action));
	pyextend_humanreadable_action(&tmpl->udp,
	    udp_action, sizeof(udp_action));

	pValue = Py_BuildValue("{ssssssssssss}",
	    "address", tmpl->name,
	    "personality", tmpl->person != NULL ? tmpl->person->name : NULL,
	    "icmp_action", icmp_action,
	    "tcp_action", tcp_action,
	    "udp_action", udp_action,
	    "ethernet", tmpl->ethernet_addr != NULL ?
	    addr_ntoa(tmpl->ethernet_addr) : NULL);
	if (pValue == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: failed to build argument list", __func__);
		exit(EXIT_FAILURE);
	}
	/* pValue reference stolen here */
	PyList_SetItem(pArgs, count->offset++, pValue);

	return (0);
}

static PyObject*
pyextend_config_ips(PyObject *self, PyObject *args)
{
	PyObject *pArgs;
	int num_ips = 0;
	struct pyextend_count count;

	/* Count all IP addresses */
	template_iterate(pyextend_count_ips, &num_ips);

	pArgs = PyList_New(num_ips);

	/* Populate tuple with per IP address information */
	memset(&count, 0, sizeof(count));
	count.pArgs = pArgs;
	template_iterate(pyextend_populate_ips, &count);

	return (pArgs);
}

static PyObject*
pyextend_stats_network(PyObject *self, PyObject *args)
{
	PyObject *pValue;
	extern struct stats_network stats_network;
	
	pValue = Py_BuildValue("{s:(d,d,d),s:(d,d,d)}",
	    "Input Bytes", 
	    (double)count_get_minute(stats_network.input_bytes)/60.0,
	    (double)count_get_hour(stats_network.input_bytes)/3600.0,
	    (double)count_get_day(stats_network.input_bytes)/86400.0,
	    "Output Bytes",
	    (double)count_get_minute(stats_network.output_bytes)/60.0,
	    (double)count_get_hour(stats_network.output_bytes)/3600.0,
	    (double)count_get_day(stats_network.output_bytes)/86400.0);

	if (pValue == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: failed to build argument list", __func__);
		exit(EXIT_FAILURE);
	}

	return (pValue);
}

static PyObject*
pyextend_config(PyObject *self, PyObject *args)
{
	PyObject *pValue;
	extern struct config config;

	pValue = Py_BuildValue("{ssssssssssss}",
	    "version", VERSION,
	    "config", config.config,
	    "personality", config.pers,
	    "xprobe", config.xprobe,
	    "assoc", config.assoc,
	    "osfp", config.osfp);
	if (pValue == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: failed to build argument list", __func__);
		exit(EXIT_FAILURE);
	}

	return (pValue);
}

static PyObject*
pyextend_interfaces(PyObject *self, PyObject *args)
{
	PyObject *pArgs;
	int i;

	pArgs = PyTuple_New(interface_count());
	for (i = 0; i < interface_count(); i++) {
		struct interface *inter = interface_get(i);
		struct intf_entry *if_ent = &inter->if_ent;
		PyObject *pValue;

		pValue = Py_BuildValue("{sssssiss}",
		    "name", if_ent->intf_name,
		    "address", addr_ntoa(&if_ent->intf_addr),
		    "mtu", if_ent->intf_mtu,
		    "link", addr_ntoa(&if_ent->intf_link_addr));
		if (pValue == NULL) {
			PyErr_Print();
			syslog(LOG_ERR, "%s: failed to build argument list", __func__);
			exit(EXIT_FAILURE);
		}
		/* pValue reference stolen here */
		PyTuple_SetItem(pArgs, i, pValue);
	}

	return (pArgs);
}

static PyObject*
pyextend_uptime(PyObject *self, PyObject *args)
{
	extern struct timeval honeyd_uptime;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	timersub(&tv, &honeyd_uptime, &tv);

	return (Py_BuildValue("i", tv.tv_sec));
}

static PyObject*
pyextend_delete_template(PyObject *self, PyObject *args)
{
	char *string;
	struct template *tmpl;
	int result = 0;

	if (!PyArg_ParseTuple(args, "s", &string))
		goto done;

	if ((tmpl = template_find(string)) == NULL)
		goto done;
	
	result = 1;
	template_remove(tmpl);

 done:
	return (Py_BuildValue("i", result));
}

static PyObject*
pyextend_delete_connection(PyObject *self, PyObject *args)
{
	extern struct tree tcpcons;
	extern struct tree udpcons;
	struct tuple tmp, *hdr;
	char *protocol;
	char *asrc, *adst, *asport, *adport;
	struct addr src, dst;
	int result = 0;

	if (!PyArg_ParseTuple(args, "sssss", &protocol,
		&asrc, &asport, &adst, &adport))
		goto done;

	if (addr_aton(asrc, &src) == -1)
		goto done;
	if (addr_aton(adst, &dst) == -1)
		goto done;

	tmp.ip_src = src.addr_ip;
	tmp.ip_dst = dst.addr_ip;
	tmp.sport = atoi(asport);
	tmp.dport = atoi(adport);

	if (!strcmp(protocol, "tcp")) {
		hdr = tuple_find(&tcpcons, &tmp);
		if (hdr == NULL)
			goto done;
		tcp_free((struct tcp_con *)hdr);
	} else if (!strcmp(protocol, "udp")) {
		hdr = tuple_find(&udpcons, &tmp);
		if (hdr == NULL)
			goto done;
		udp_free((struct udp_con *)hdr);
	}
	
	result = 1;

 done:
	return (Py_BuildValue("i", result));
}

static PyObject*
pyextend_log(PyObject *self, PyObject *args)
{
	extern FILE *honeyd_servicefp;
	struct tuple *hdr;
	char *string;

	if (current_state == NULL)
		return (Py_BuildValue("i", -1));
	
	hdr = current_state->con;
	
	if(!PyArg_ParseTuple(args, "s:read_selector", &string))
		return (NULL);

	honeyd_log_service(honeyd_servicefp,
	    hdr->type == SOCK_STREAM ? IP_PROTO_TCP : IP_PROTO_UDP,
	    hdr, string);

	return (Py_BuildValue("i", 0));
}

static PyObject*
pyextend_raw_log(PyObject *self, PyObject *args)
{
	char *string;

	if(!PyArg_ParseTuple(args, "s:read_selector", &string))
		return (NULL);

	syslog(LOG_NOTICE, "%s", string);

	return Py_BuildValue("i", 0);;
}

static PyObject*
pyextend_selector(PyObject *args, struct event *ev, const char *name)
{
	int on = 0;

	if(!PyArg_ParseTuple(args, "i:read_selector", &on))
		return (NULL);
	DFPRINTF(1, (stderr, "%s: called selector with %d\n", name, on));

	if (on)
		event_add(ev, NULL);
	else
		event_del(ev);

	return Py_BuildValue("i", 0);;
}

static PyObject*
pyextend_readselector(PyObject *self, PyObject *args)
{
	if (current_state == NULL)
		return (NULL);

	return (pyextend_selector(args, &current_state->pread, __func__));
}

static PyObject*
pyextend_writeselector(PyObject *self, PyObject *args)
{
	struct pystate *state = current_state;

	PyObject *pValue;
	if (state == NULL)
		return (NULL);

	pValue = pyextend_selector(args, &state->pwrite, __func__);
	if (pValue == NULL)
		return (NULL);

	/* 
	 * We need to keep track of this, so that in case we have buffered
	 * data to write, we know if we should schedule the python script.
	 */
	state->wantwrite = event_pending(&state->pwrite, EV_WRITE, NULL);

	return (pValue);
}

static void
pyextend_cbread(int fd, short what, void *arg)
{
	static char buf[4096];
	PyObject *pArgs, *pValue;
	struct pystate *state = arg;
	struct pyextend *pye = state->pye;
	int n;

	n = read(fd, buf, sizeof(buf));

	if (n <= 0)
		goto error;

	pArgs = Py_BuildValue("(O,s#)", state->state, buf, n);
	if (pArgs == NULL) {
		fprintf(stderr, "Failed to build value\n");
		goto error;
	}

	current_state = state;
	pValue = PyObject_CallObject(pye->pFuncReadData, pArgs);
	current_state = NULL;

	Py_DECREF(pArgs);

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}
	Py_DECREF(pValue);

	return;

 error:
	pyextend_connection_end(state);
	return;
}

static int
pyextend_addbuffer(struct pystate *state, u_char *buf, size_t size)
{
	struct pywrite *write;

	if ((write = malloc(sizeof(struct pywrite))) == NULL)
		return (-1);

	if ((write->buf = malloc(size)) == NULL) {
		free(write);
		return (-1);
	}

	memcpy(write->buf, buf, size);
	write->size = size;

	TAILQ_INSERT_TAIL(&state->writebuffers, write, next);

	return (0);
}

static void
pyextend_cbwrite(int fd, short what, void *arg)
{
	PyObject *pArgs, *pValue;
	struct pystate *state = arg;
	struct pyextend *pye = state->pye;
	struct pywrite *writebuf;
	char *buf;
	int size, res;

	/* If we still have buffered data from before, we are going
	 * to send it now and reschedule us if necessary.
	 */
	if ((writebuf = TAILQ_FIRST(&state->writebuffers)) != NULL) {
		res = write(fd, writebuf->buf, writebuf->size);
		if (res <= 0)
			goto error;
		if (res < writebuf->size) {
			writebuf->size -= res;
			memmove(writebuf->buf, writebuf->buf + res,
			    writebuf->size);
			event_add(&state->pwrite, NULL);
		} else {
			TAILQ_REMOVE(&state->writebuffers, writebuf, next);
			free(writebuf->buf);
			free(writebuf);
			if (state->wantwrite ||
			    TAILQ_FIRST(&state->writebuffers) != NULL)
				event_add(&state->pwrite, NULL);
		}

		return;
	}
	

	pArgs = Py_BuildValue("(O)", state->state);
	if (pArgs == NULL) {
		fprintf(stderr, "Failed to build value\n");
		goto error;
	}

	current_state = state;
	pValue = PyObject_CallObject(pye->pFuncWriteData, pArgs);
	current_state = NULL;

	Py_DECREF(pArgs);

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}

	/* 
	 * Addition to support closing connections from the server
	 * side. - AJ 2.4.2004
	 */
	if (pValue == Py_None) {
		Py_DECREF(pValue);
		goto error;
	}

	res = PyString_AsStringAndSize(pValue, &buf, &size);

	if (res == -1) {
		Py_DECREF(pValue);
		goto error;
	}

	/* XXX - What to do about left over data */
	res = write(fd, buf, size);

	if (res <= 0) {
		Py_DECREF(pValue);
		goto error;
	}

	if (res != size) {
		pyextend_addbuffer(state, buf + res, size - res);
		event_add(&state->pwrite, NULL);
	}

	Py_DECREF(pValue);
		
	return;

 error:
	pyextend_connection_end(state);
	return;
}

/* Initializes our Python extension support */

void
pyextend_init(void)
{
	PyObject *pModule;
	char path[1024], singlepath[1024];
	extern char *honeyd_webserver_root;
	char *p;

	SPLAY_INIT(&pyextends);

	Py_Initialize();
	strlcpy(path, Py_GetPath(), sizeof(path));
	/* Append the current path */
	strlcat(path, ":.", sizeof(path));
	strlcat(path, ":webserver", sizeof(path));

	/* Append the webserver root directory */
	snprintf(singlepath, sizeof(singlepath), ":%s", honeyd_webserver_root);
	if ((p = strstr(singlepath, "/htdocs")) != NULL) {
		*p = '\0';
		strlcat(path, singlepath, sizeof(path));
	}

	/* Append the Honeyd shared data directory */ 
	snprintf(singlepath, sizeof(singlepath),
	    ":%s", PATH_HONEYDDATA);
	strlcat(path, singlepath, sizeof(path));
	snprintf(singlepath, sizeof(singlepath),
	    ":%s/webserver", PATH_HONEYDDATA);
	strlcat(path, singlepath, sizeof(path));
	PySys_SetPath(path);

	pModule = Py_InitModule("honeyd", HoneydMethods);
	PyModule_AddIntConstant(pModule, "EVENT_ON", 1);
	PyModule_AddIntConstant(pModule, "EVENT_OFF", 0);
	PyModule_AddStringConstant(pModule, "version", VERSION);
}

/* Cleans up all Python stuff when we exit */

void
pyextend_exit(void)
{
	Py_Finalize();
}

void
pyextend_run(struct evbuffer *output, char *command)
{
	PyObject *res = NULL, *compiled_code;
	char *data;
	int datlen;

	char *preamble = "import StringIO\n"
	    "import sys\n"
	    "myout = StringIO.StringIO()\n"
	    "myerr = StringIO.StringIO()\n"
	    "saveout = sys.stdout\n"
	    "saveerr = sys.stderr\n"
	    "try:\n"
	    "  sys.stdout = myout\n"
	    "  sys.stderr = myerr\n"
	    "  try:\n"
	    "    %s\n"
	    "  except:\n"
	    "    import traceback\n"
	    "    traceback.print_exc()\n"
	    "finally:\n"
	    "  sys.stdout = saveerr\n"
	    "  sys.stderr = saveerr\n"
	    "output = \"%%s%%s\" %% (myout.getvalue(), myerr.getvalue())";

	char *code = NULL;

	if (asprintf(&code, preamble, command) == -1)
	{
		syslog(LOG_ERR, "%s: asprintf", __func__);
		exit(EXIT_FAILURE);
	}

	compiled_code = Py_CompileStringFlags(code, "<filter>",
	    Py_file_input, 0);

	free(code);
	
	if (compiled_code == NULL) {
		const char *err = "Compilation of Python code failed.\n";
		evbuffer_add(output, (char *)err, strlen(err));
		PyErr_Print();
		return;
	}

	if (pyextend_dict_local == NULL) {
		pyextend_dict_local = PyDict_New();
		assert(pyextend_dict_local != NULL);
	}
	
	if (pyextend_dict_global == NULL) {
		PyObject *m;

		/* Extract the global dictionary object */
		if ((m = PyImport_AddModule("__main__")) == NULL) {
			PyErr_Print();
			return;
		}

		if ((pyextend_dict_global = PyModule_GetDict(m)) == NULL) {
			PyErr_Print();
			return;
		}
		Py_INCREF(pyextend_dict_global);

		if (PyDict_GetItemString(pyextend_dict_global, "__builtins__") == NULL&&
		    PyDict_SetItemString(pyextend_dict_global, "__builtins__", PyEval_GetBuiltins()) == 0) {
			Py_DECREF(pyextend_dict_global);
			pyextend_dict_global = NULL;
			return;
		}
	}

	res = PyEval_EvalCode((PyCodeObject *)compiled_code,
	    pyextend_dict_global, pyextend_dict_local);
	Py_DECREF(compiled_code);

	if (res == NULL) {
		PyErr_Print();
		return;
	}
	Py_DECREF(res);

	res = PyDict_GetItemString(pyextend_dict_local, "output");
	assert(res != NULL);

	if (PyString_AsStringAndSize(res, &data, &datlen) == 0) 
		evbuffer_add(output, data, datlen);
}

#define CHECK_FUNC(f, x) do { \
	f = PyDict_GetItemString(pDict, x); \
	if ((f) == NULL || !PyCallable_Check(f)) { \
		warnx("%s: Cannot find function \"%s\"", \
			__func__, x); \
		goto error; \
	} \
} while (0)

void *
pyextend_load_module(const char *name)
{
	PyObject *pName, *pModule, *pDict, *pFunc;
	struct pyextend *pye, tmp;

	char line[1024];
	char *script, *p;
	
	if (strlcpy(line, name, sizeof(line)) >= sizeof(line))
		return (NULL);
	p = line;

	script = strsep(&p, " ");

	tmp.name = script;
	if ((pye = SPLAY_FIND(pyetree, &pyextends, &tmp)) != NULL)
		return (pye);

	pName = PyString_FromString(script);
	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule == NULL) {
		PyErr_Print();
		warn("%s: could not load python module: %s",
		    __func__, script);
		return (NULL);
	}

	pDict = PyModule_GetDict(pModule); /* Borrowed */

	CHECK_FUNC(pFunc, "honeyd_init");
	CHECK_FUNC(pFunc, "honeyd_readdata");
	CHECK_FUNC(pFunc, "honeyd_writedata");
	CHECK_FUNC(pFunc, "honeyd_end");

	if ((pye = calloc(1, sizeof(struct pyextend))) == NULL)
	{
		syslog(LOG_ERR, "calloc");
		exit(EXIT_FAILURE);
	}
		//err(1, "calloc");

	CHECK_FUNC(pye->pFuncInit, "honeyd_init");
	CHECK_FUNC(pye->pFuncReadData, "honeyd_readdata");
	CHECK_FUNC(pye->pFuncWriteData, "honeyd_writedata");
	CHECK_FUNC(pye->pFuncEnd, "honeyd_end");

	if ((pye->name = strdup(script)) == NULL)
	{
		syslog(LOG_ERR, "%s: strdup", __func__);
		exit(EXIT_FAILURE);
	}

	SPLAY_INSERT(pyetree, &pyextends, pye);
	  
	return (pye);

 error:
	Py_DECREF(pModule);
	return (NULL);
}

static struct pystate *
pyextend_newstate(struct command *cmd, void *con, struct pyextend *pye)
{
	struct pystate *state;

	if ((state = calloc(1, sizeof(struct pystate))) == NULL)
		return (NULL);

	/* Initialize structure */
	state->fd = -1;
	state->cmd = cmd;
	state->con = con;
	state->pye = pye;

	TAILQ_INIT(&state->writebuffers);

	return (state);
}

static void
pyextend_freestate(struct pystate *state)
{
	struct pywrite *writes;

	while ((writes = TAILQ_FIRST(&state->writebuffers)) != NULL) {
		TAILQ_REMOVE(&state->writebuffers, writes, next);
		free(writes->buf);
		free(writes);
	}

	/* Cleanup our state */
	event_del(&state->pread);
	event_del(&state->pwrite);

	if (state->fd != -1)
		close(state->fd);
	free(state);
}

int
pyextend_connection_start(struct tuple *hdr, struct command *cmd,
    void *con, void *pye_generic)
{
	struct pyextend *pye = pye_generic;
	struct pystate *state;
	PyObject *pArgs, *pValue;
	struct addr src, dst;
	struct ip_hdr ip;
	char *os_name = NULL;

	if ((state = pyextend_newstate(cmd, con, pye)) == NULL)
		return (-1);

	if ((state->fd = cmd_python(hdr, cmd, con)) == -1) {
		free(state);
		return (-1);
	}

	/* Set up state with event callbacks */
	event_set(&state->pread, state->fd, EV_READ, pyextend_cbread, state);
	event_set(&state->pwrite, state->fd, EV_WRITE, pyextend_cbwrite,state);

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);

	/* Determine the remote operating system */
	ip.ip_src = hdr->ip_src;
	os_name = honeyd_osfp_name(&ip);

	pArgs = PyTuple_New(1);
	pValue = Py_BuildValue("{sssssisiss}",
	    "HONEYD_IP_SRC", addr_ntoa(&src),
	    "HONEYD_IP_DST", addr_ntoa(&dst),
	    "HONEYD_SRC_PORT", hdr->sport,
	    "HONEYD_DST_PORT", hdr->dport,
	    "HONEYD_REMOTE_OS", os_name);
	if (pValue == NULL) {
		fprintf(stderr, "Failed to build value\n");
		Py_DECREF(pArgs);
		goto error;
	}

	/* Set up the current state for Python */
	current_state = state;

	/* pValue reference stolen here: */
	PyTuple_SetItem(pArgs, 0, pValue);

	pValue = PyObject_CallObject(pye->pFuncInit, pArgs);
	Py_DECREF(pArgs);

	/* Take away the current state */
	current_state = NULL;

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}

	state->state = pValue;

	/* 
	 * Registers state with command structure so that we can do
	 * proper cleanup if things go wrong.
	 */
	cmd->state = state;
	return (0);
	
 error:
	pyextend_freestate(state);
	return (-1);
}

void
pyextend_connection_end(struct pystate *state)
{
	struct command *cmd = state->cmd;
	struct pyextend *pye = state->pye;
	PyObject *pArgs;

	pArgs = PyTuple_New(1);

	/* state->state reference stolen here: */
	PyTuple_SetItem(pArgs, 0, state->state);

	PyObject_CallObject(pye->pFuncEnd, pArgs);
	Py_DECREF(pArgs);

	pyextend_freestate(state);

	cmd->state = NULL;

	return;
}

/*
 * We register our own web server so that we can get some stats reporting
 * via a web browser.
 */

static PyObject *pWebServer;	/* web server instance */
static PyObject *pFuncRequest;	/* handle request function */

static int pyserver_fd = -1;
static struct event ev_accept;

void pyextend_request_free(struct pyextend_request *);

void
pyextend_evb_readcb(struct bufferevent *bev, void *parameter)
{
	struct pyextend_request *req = parameter;
	PyObject *pArgs, *pValue;
	char *client_address = addr_ntoa(&req->src);
	char *buf;
	int size, res;

	/* Check if we have received the complete request */
	if (evbuffer_find(bev->input, "\r\n\r\n", 4) == NULL) {
		/* 
		 * If we did not receive the complete request and we have
		 * waited for too long already, then we drop the request.
		 */
		if (EVBUFFER_LENGTH(bev->input) > PYEXTEND_MAX_REQUEST_SIZE) {
			syslog(LOG_NOTICE,
			    "Dropping request from %s with size %d",
			    client_address, EVBUFFER_LENGTH(bev->input));
			pyextend_request_free(req);
		}
		return;
	}

	pArgs = Py_BuildValue("(O,s#,s#)", pWebServer,
	    EVBUFFER_DATA(bev->input), EVBUFFER_LENGTH(bev->input),
	    client_address, strlen(client_address));
	if (pArgs == NULL)
		goto error;

	pValue = PyObject_CallObject(pFuncRequest, pArgs);
	Py_DECREF(pArgs);

	if (pValue == NULL)
		goto error;

	res = PyString_AsStringAndSize(pValue, &buf, &size);

	if (res == -1) {
		Py_DECREF(pValue);
		goto error;
	}

	/* Write the data to the network stream and be done with it */
	bufferevent_write(req->evb, buf, size);

	return;

 error:
	PyErr_Print();
	pyextend_request_free(req);
}

void
pyextend_evb_writecb(struct bufferevent *bev, void *parameter)
{
	/* 
	 * At this point, we have written all of our result data, so
	 * we just close the connection.
	 */
	struct pyextend_request *req = parameter;
	pyextend_request_free(req);
}

void
pyextend_evb_errcb(struct bufferevent *bev, short what, void *parameter)
{
	struct pyextend_request *req = parameter;
	pyextend_request_free(req);
}

/* Frees a request object and closes the connection */

void
pyextend_request_free(struct pyextend_request *req)
{
	bufferevent_free(req->evb);
	close(req->fd);
	free(req);
}

/* Creates a request object that can be used for streaming data */

struct pyextend_request *
pyextend_request_new(int fd, struct addr *src)
{
	struct pyextend_request *req = NULL;

	if ((req = calloc(1, sizeof(struct pyextend_request))) == NULL)
		return (NULL);

	req->fd = fd;
	req->src = *src;

	if ((req->evb = bufferevent_new(fd,
		 pyextend_evb_readcb, pyextend_evb_writecb, pyextend_evb_errcb,
		 req)) == NULL) {
		free(req);
		return (NULL);
	}

	/* Highest priority to UI requests */
	bufferevent_priority_set(req->evb, 0);

	bufferevent_enable(req->evb, EV_READ);	
	return (req);
}

void
pyextend_accept(int fd, short what, void *arg)
{
	struct sockaddr_storage ss;
	socklen_t socklen = sizeof(ss);
	struct addr src;
	struct pyextend_request *req = NULL;
	int newfd;

	if ((newfd = accept(fd, (struct sockaddr *)&ss, &socklen)) == -1) {
		warn("%s: accept", __func__);
		return;
	}

	addr_ston((struct sockaddr *)&ss, &src);
	syslog(LOG_DEBUG, "%s: new request from %s",
	    __func__, addr_ntoa(&src));

	/* Create a new request structure and dispatch the request */
	if ((req = pyextend_request_new(newfd, &src)) == NULL) {
		warn("%s: calloc", __func__);
		close(newfd);
		return;
	}
}

void
pyextend_webserver_fix_permissions(const char *path, uid_t uid, gid_t gid)
{
	static int created_dirs;
	DIR *dir;
	struct dirent *file;
	struct stat sb;
	char fullname[PATH_MAX];
	int off;

	/* Create special directories */
	if (!created_dirs) {
		created_dirs = 1;
		if (snprintf(fullname, sizeof(fullname), "%s/graphs", path) >=
		    sizeof(fullname))
		{
			syslog(LOG_ERR, "Path too long: %s\graphs", path);
			exit(EXIT_FAILURE);
		}
		if (lstat(fullname, &sb) == -1 && errno == ENOENT) {
			syslog(LOG_INFO, "Creating directory %s", fullname);
			if (mkdir(fullname, 0722) == -1)
			{
				syslog(LOG_ERR, "mkdir(%s)", fullname);
				exit(EXIT_FAILURE);
			}
		}
	}

	/* Fix permissions */
	if (strlen(path) >= sizeof (fullname) - 2)
	{
		syslog(LOG_ERR, "directory name too long");
		exit(EXIT_FAILURE);
	}

	dir = opendir(path);
	if (dir == NULL)
	{
		syslog(LOG_ERR, "opendir(%s)", path);
		exit(EXIT_FAILURE);
	}

	strlcpy(fullname, path, sizeof (fullname));
	off = strlen(fullname);
	if (fullname[off - 1] != '/') {
		strlcat(fullname, "/", sizeof(fullname));
		off++;
	}

	while ((file = readdir(dir)) != NULL) {
		char *filename = file->d_name;
		if (!strcmp(filename, "..") || !strcmp(filename, "CVS"))
			continue;

		strlcpy(fullname + off, filename, sizeof(fullname) - off);

		if (lstat(fullname, &sb) == -1)
		{
			syslog(LOG_ERR, "lstat(%s)", fullname);
			exit(EXIT_FAILURE);
		}

		/* We ignore symbolic links - shoot yourself in the foot */
		if (sb.st_mode & S_IFLNK)
			continue;

		/* Change owner ship to us */
		if (sb.st_uid != uid || sb.st_gid != gid) {
			syslog(LOG_INFO, "Fixing ownership: %s", fullname);
			if (chown(fullname, uid, gid) == -1)
			{
				syslog(LOG_ERR, "chown(%s)", fullname);
				exit(EXIT_FAILURE);
			}
		}

		if ((sb.st_mode & (S_IRUSR|S_IWUSR)) != (S_IRUSR|S_IWUSR) ||
		    (sb.st_mode & S_IWOTH)) {
			int mode = (sb.st_mode & 0777);
			mode |= (S_IRUSR|S_IWUSR);
			/* No write access for others */
			mode &= ~S_IWOTH;

			syslog(LOG_INFO, "Fixing modes: %s", fullname);
			if (chmod(fullname, mode) == -1)
			{
				syslog(LOG_ERR, "chmod(%s)", fullname);
				exit(EXIT_FAILURE);
			}
		}

		if ((sb.st_mode & S_IFDIR) && filename[0] != '.')
			pyextend_webserver_fix_permissions(fullname, uid, gid);
	}
	closedir(dir);
}

void
pyextend_webserver_verify_setup(const char *root_dir)
{
	char filename[1024];
	struct _dirs {
		const char *path;
		int mode;
	} dirs[] = { 
		{ "styles", R_OK },
		{ "images", R_OK },
		{ ".", W_OK|R_OK },
		{ "graphs", W_OK|R_OK },
		{ "templates", W_OK|R_OK },
		{ NULL, 0 }
	};
	struct _dirs *p;

	for (p = &dirs[0]; p->path != NULL; p++) {
		snprintf(filename, sizeof(filename), "%s/%s",
		    root_dir, p->path);
		if (access(filename, p->mode) == -1) {
			syslog(LOG_ERR,
			    "webserver: require%s%s access to %s: %m",
			    p->mode & W_OK ? " write" : "",
			    p->mode & R_OK ? " read" : "",
			    filename);
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * Intializes the Python webserver.  It listens on the specified port
 * and serves documents from the specified directory.
 */

void
pyextend_webserver_init(char *address, int port, char *root_dir)
{
	PyObject *pArgs, *pName, *pModule, *pDict, *pFuncWebInit;
	char *script = "server";

	pName = PyString_FromString(script);
	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: could not load python module: %s", __func__, script);
		exit(EXIT_FAILURE);
	}

	pDict = PyModule_GetDict(pModule); /* Borrowed */

	CHECK_FUNC(pFuncWebInit, "make_server");
	CHECK_FUNC(pFuncRequest, "handle_request");
	pArgs = Py_BuildValue("(s)", root_dir);
	if (pArgs == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: Failed to build value", __func__);
		exit(EXIT_FAILURE);
	}
	pWebServer = PyObject_CallObject(pFuncWebInit, pArgs);
	Py_DECREF(pArgs);
	if (pWebServer == NULL) {
		PyErr_Print();
		syslog(LOG_ERR, "%s: make_server function returned error.", __func__);
		exit(EXIT_FAILURE);
	}

	pyserver_fd = make_socket(bind, SOCK_STREAM, address, port);

	if (pyserver_fd == -1) {
		fprintf(stderr,
		    "\nA web server might already be running on port %d.\n"
		    "Choose another port via --webserver-port or disable\n"
		    "the built in webserver via --disable-webserver.\n", port);
		exit(1);
	}

	if (listen(pyserver_fd, 10) == -1)
	{
		syslog(LOG_ERR, "%s: listen", __func__);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "HTTP server listening on %s:%d", address, port);
	syslog(LOG_NOTICE, "HTTP server root at %s", root_dir);
	
	/* Accept connections */
	event_set(&ev_accept, pyserver_fd, EV_READ | EV_PERSIST,
	    pyextend_accept, NULL);

	/* Give the highest priority to the accept */
	event_priority_set(&ev_accept, 0);
	event_add(&ev_accept, NULL);
	return;

 error:
	Py_DECREF(pModule);
	syslog(LOG_ERR, "Cannot initialize module");
	exit(EXIT_FAILURE);
}

void
pyextend_webserver_exit(void)
{
	event_del(&ev_accept);
	close(pyserver_fd);
}
