#include "Python.h"
#include "structmember.h"

typedef struct {
	PyObject_HEAD
	Py_buffer* keys;
	int number;
} Crypto;

static void Crypto_dealloc(Crypto* self)
{
	free(self->keys);
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
Crypto_new(PyTypeObject *type, PyObject *args, PyObject *kwds){
		Crypto *self;
		Py_buffer* placeholder = NULL;
		self = (Crypto*)type->tp_alloc(type, 0);
		if (self != NULL){
			self->keys = placeholder;
			if (self->keys != NULL){
				Py_DECREF(self);
				return NULL;
			}
			self->number = 0;
		}
		return (PyObject*) self;}

static int
	Crypto_init(Crypto* self, PyObject* args, PyObject *kwds){
		Py_buffer* temp = NULL;
		Py_buffer* keysbuf  = (Py_buffer*)malloc(sizeof(Py_buffer));
		if (!PyArg_ParseTuple(args, "y*", keysbuf))
			return -1;
		if (keysbuf){
			if (keysbuf->len != 160){
				free(keysbuf);
				return -1;
			}
			else {
				temp = self->keys;
				Py_INCREF(keysbuf);
				self->keys = keysbuf;
				Py_XDECREF(temp);				
				printf("set field ...");
			}
		}		
		return 0;
}

static PyMemberDef Crypto_members[] = {
	{"keys", T_OBJECT_EX, offsetof(Crypto, keys), 0,
	"array of keys"},
	{"number", T_INT, offsetof(Crypto, number), 0,
	"crypto number"},
	{NULL} /*sentinel*/
};

static PyObject*
	Crypto_name(Crypto *self){
	if (self->keys == NULL){
		PyErr_SetString(PyExc_AttributeError, "keys");
		return NULL;}
	return Py_BuildValue("y#", self->keys->buf, 160);
}

static PyMethodDef Crypto_methods[] = {
	{"name", (PyCFunction)Crypto_name, METH_NOARGS,
	"Prints the keys"
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