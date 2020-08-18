/*
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
*/

#include "Python.h"
#include <stdlib.h>
#include <stdio.h>


extern int quote_main(FILE *outStream, int argc, char *argv[]);
extern int checkquote_main(FILE *outStream, int argc, char *argv[]);
const char *checkquote_argv[] = {"checkquote", "-quote", "vquote/quote.bin", "-nonce", "1", "-aik", "vquote/aik.bin"};



static PyObject *call_keylime(int (*keylime_fn)(FILE *, int, char **),
			      char *fn_name,
			      PyObject *self,
			      PyObject *args)
{
	int i;
	int rc;
	PyObject *result = NULL;
	Py_ssize_t len = PyTuple_Size(args);
	char **argv = calloc(len+1, sizeof(*argv));
	int argc = 0;
	char *outBuf = NULL;
	size_t outBuf_len;
	FILE *outStream = open_memstream(&outBuf, &outBuf_len);
	argv[argc++] = fn_name;
	for (i=0; i < len; i++) {
		PyObject *item = PyTuple_GetItem(args, i);
		if  (!(PyString_Check(item))) {
			PyErr_Format(PyExc_RuntimeError,
				     "Argument %d to '%s' was not a string.", i, fn_name);
			result = NULL;
			goto cleanup;
		}
		assert((argc <= len) && "Invalid length for argc");
		argv[argc++] = PyString_AsString(item);
	}
	/* The keylime_fn is a call into the tpm4720 package and won't be making
	 * making use of python objects, so we can release the GIL for its duration.
	 * This only helps if a separate python thread is running.
	 */
	Py_BEGIN_ALLOW_THREADS
	rc = keylime_fn(outStream, argc, argv);
	Py_END_ALLOW_THREADS
	if (rc != 0) {
		PyErr_Format(PyExc_RuntimeError,
			     "'%s' returned with non-zero code '%d'.", fn_name, rc);
		goto cleanup;
	}
	fclose(outStream);
	result = Py_BuildValue("s", outBuf);
cleanup:
	free(argv);
	free(outBuf);
	return result;
}

static PyObject *checkquote(PyObject *self, PyObject *args)
{
	return call_keylime(checkquote_main, "checkquote", self, args);
}

static PyObject *quote(PyObject *self, PyObject *args)
{
	return call_keylime(quote_main, "quote", self, args);
}

static PyMethodDef module_functions[] = {
	{ "checkquote", checkquote, METH_VARARGS, "Run checkquote." },
	{ "quote", quote, METH_VARARGS, "Run quote." },
	{ NULL }
};

void init_cLime(void)
{
	Py_InitModule3("_cLime", module_functions, "Keylime C module");
}
