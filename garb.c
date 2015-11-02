#include "Python.h"
#include "structmember.h"

typedef struct {
	PyObject_HEAD
	PyObject* first;
	PyObject* last;
	int number;
} Crypto;

static void Crypto_dealloc(Crypto* self)
{
	Py_XDECREF(self->first);
	Py_XDECREF(self->last);
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
Crypto_new(PyTypeObject *type, PyObject *args, PyObject *kwds){
		Crypto *self;
		self = (Crypto*)type->tp_alloc(type, 0);
		if (self != NULL){
			self->first = PyUnicode_FromString("");
			if (self->first == NULL){
				Py_DECREF(self);
				return NULL;
			}

			self->last = PyUnicode_FromString("");
			if (self->last == NULL){
				Py_DECREF(self);
				return NULL;
			}
			self->number = 0;
		}
		return (PyObject*) self;}

static int
	Crypto_init(Crypto* self, PyObject* args, PyObject *kwds){
		PyObject* first = NULL, *last = NULL, *tmp;
		static char *kwlist[] = {"first", "last", "number", NULL};

		if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOi", kwlist,
			&first, &last, &self->number))
			return -1;
		if (first){
			tmp = self->first;
			Py_INCREF(first);
			self->first = first;
			Py_XDECREF(tmp);
		}
		if (last){
			tmp = self->last;
			Py_INCREF(last);
			self->last = last;
			Py_XDECREF(tmp);
		}
		return 0;
}

static PyMemberDef Crypto_members[] = {
	{"first", T_OBJECT_EX, offsetof(Crypto, first), 0,
	"first name"},
	{"last", T_OBJECT_EX, offsetof(Crypto, last), 0,
	"last name"},
	{"number", T_INT, offsetof(Crypto, number), 0,
	"crypto number"},
	{NULL} /*sentinel*/
};

static PyObject*
	Crypto_name(Crypto *self){
	if (self->first == NULL){
		PyErr_SetString(PyExc_AttributeError, "first");
		return NULL;}
	if (self->last == NULL){
		PyErr_SetString(PyExc_AttributeError, "last");
		return NULL;}
	return PyUnicode_FromFormat("%S %S", self->first, self->last);
}

static PyMethodDef Crypto_methods[] = {
	{"name", (PyCFunction)Crypto_name, METH_NOARGS,
	"Return the name, combining the first and last name"
	},
	{NULL} /*sentinel here too*/
};

static PyTypeObject CryptoType = {
	PyVarObject_HEAD_INIT(NULL, 0)
        "crypto.Crypto",
	sizeof(Crypto),
	0,
	(destructor)Crypto_dealloc,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	"Crypto objects",
	0,
	0,
	0,
	0,
	0,
	0,
	Crypto_methods,
	Crypto_members,
	0,
	0,
	0,
	0,
	0,
	0,
	(initproc)Crypto_init,
	0,
	Crypto_new,
};

static PyModuleDef cryptolibmodule = {
	PyModuleDef_HEAD_INIT,
        "cryptolib",
        "Cryptolib for galois mul",
        -1,
        NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit_cryptolib(void){
	PyObject *module;
		
	if (PyType_Ready(&CryptoType) < 0)
		return NULL;
	module = PyModule_Create(&cryptolibmodule);
	if (module == NULL)
		return NULL;
	Py_INCREF(&CryptoType);
	PyModule_AddObject(module, "Crypto", (PyObject *)&CryptoType);
	return module;
}