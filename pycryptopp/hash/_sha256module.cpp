/**
 * _sha256module.cpp -- Python wrappers around Crypto++'s SHA-256
 */

#include <Python.h>

/* from Crypto++ */
#ifdef USE_NAME_CRYPTO_PLUS_PLUS
// for Debian (and Ubuntu, and their many derivatives)
//#include "crypto++/filters.h"
//#include "crypto++/osrng.h"
//#include "crypto++/pssr.h"
//#include "crypto++/randpool.h"
//#include "crypto++/rsa.h"
#include "crypto++/sha.h"
#else
// for upstream Crypto++ library
//#include "cryptopp/filters.h"
//#include "cryptopp/osrng.h"
//#include "cryptopp/pssr.h"
//#include "cryptopp/randpool.h"
//#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#endif

static char sha256__doc__[] = "\
sha256 hash function\n\
\n\
To create a new RSA signing key from the operating system's random number generator, call generate().\n\
To create a new RSA signing key from a seed, call generate_from_seed().\n\
To deserialize an RSA signing key from a string, call create_signing_key_from_string().\n\
\n\
To get an RSA verifying key from an RSA signing key, call get_verifying_key() on the signing key.\n\
To deserialize an RSA verifying key from a string, call create_verifying_key_from_string().\n\
";

/* NOTE: if the complete expansion of the args (by vsprintf) exceeds 1024 then memory will be invalidly overwritten. */
/* (We don't use vsnprintf because Microsoft standard libraries don't support it.) */
static PyObject *sha256_error;
static PyObject *
raise_sha256_error(const char *format, ...) {
    char exceptionMsg[1024];
    va_list ap;

    va_start (ap, format);
    vsprintf (exceptionMsg, format, ap); /* Make sure that this can't exceed 1024 chars! */
    va_end (ap);
    exceptionMsg[1023]='\0';
    PyErr_SetString (sha256_error, exceptionMsg);
    return NULL;
}

typedef struct {
    PyObject_HEAD

    /* internal */
    CryptoPP::SHA256 h;
    PyStringObject* digest;
} SHA256;

PyDoc_STRVAR(SHA256__doc__,
"A SHA256 hash object.");

static PyObject *
SHA256_update(SHA256* self, PyObject* msgobj) {
    if (self->digest)
        return raise_sha256_error("Precondition violation: once .digest() has been called you are required to never call .update() again.");

    const char *msg;
    size_t msgsize;
    PyString_AsStringAndSize(msgobj, const_cast<char**>(&msg), reinterpret_cast<int*>(&msgsize));
    self->h.Update(reinterpret_cast<const byte*>(msg), msgsize);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SHA256_update__doc__,
"Update the hash object with the string msg. Repeated calls are equivalent to\n\
a single call with the concatenation of all the messages.");

static PyObject *
SHA256_digest(SHA256* self, PyObject* dummy) {
    if (!self->digest) {
        self->digest = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, self->h.DigestSize()));
        if (!self->digest)
            return NULL;
        self->h.Final(reinterpret_cast<byte*>(PyString_AS_STRING(self->digest)));
    }

    Py_INCREF(self->digest);
    return reinterpret_cast<PyObject*>(self->digest);
}

PyDoc_STRVAR(SHA256_digest__doc__,
"Return the binary digest of the messages that were passed to the update()\n\
method (including the initial message if any) so far.");

static PyMethodDef SHA256_methods[] = {
    {"update", reinterpret_cast<PyCFunction>(SHA256_update), METH_VARARGS, SHA256_update__doc__},
    {"digest", reinterpret_cast<PyCFunction>(SHA256_digest), METH_NOARGS, SHA256_digest__doc__},
    {NULL},
};

static PyTypeObject SHA256_type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_sha256.SHA256", /*tp_name*/
    sizeof(SHA256),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    0,                         /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    SHA256__doc__,           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    SHA256_methods,      /* tp_methods */
};

static PyObject *
SHA256_new(PyObject* dummy, PyObject *args, PyObject *kwdict) {
    static char *kwlist[] = { "string", NULL };
    const char *initmsg;
    size_t initmsgsize;
    if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#", const_cast<char**>(kwlist), &initmsg, &initmsgsize))
        return NULL;

    SHA256* self = reinterpret_cast<SHA256*>(SHA256_type.tp_alloc(&SHA256_type, 0));

    self->h.Update(reinterpret_cast<const byte*>(initmsg), initmsgsize);
    return reinterpret_cast<PyObject*>(self);
}

PyDoc_STRVAR(SHA256_new__doc__,
"Return a new SHA256 hash object, optionally initialized with a string.");

static struct PyMethodDef sha256_functions[] = {
    {"SHA256", reinterpret_cast<PyCFunction>(SHA256_new), METH_KEYWORDS, SHA256_new__doc__},
    {NULL,	NULL}		 /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
init_sha256(void) {
    PyObject *module;
    PyObject *module_dict;

    if (PyType_Ready(&SHA256_type) < 0)
        return;

    module = Py_InitModule3("_sha256", sha256_functions, sha256__doc__);
    if (module == NULL)
      return;

    Py_INCREF(&SHA256_type);

    PyModule_AddObject(module, "SHA256", (PyObject *)&SHA256_type);

    module_dict = PyModule_GetDict(module);
    sha256_error = PyErr_NewException("_sha256.Error", NULL, NULL);
    PyDict_SetItemString(module_dict, "Error", sha256_error);
}
