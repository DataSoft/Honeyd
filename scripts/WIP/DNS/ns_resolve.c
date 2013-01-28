#include <Python.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

static PyObject* get_ns_list(PyObject *self, PyObject *args)
{
  int i;
  res_init();
  char *test;
  
  if(_res.nscount < 1)
  {
    return NULL;
  }

  PyObject *py[_res.nscount];

  for(i = 0; i < _res.nscount; i++)
  {
    test = inet_ntoa(_res.nsaddr_list[i].sin_addr);
    py[i] = Py_BuildValue("s", test); 
  }

  return py;
}

static PyMethodDef NSMethods[] = {
  {"get_ns_list", get_ns_list, METH_VARARGS, "Determine host's DNS server for packet pass-through"},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC 
initgetns(void)
{
  (void) Py_InitModule("get_ns", NSMethods);
}

