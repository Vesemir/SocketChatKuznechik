#include "Python.h"
#include "structmember.h"
#include "stdio.h"
/*CONSTANTS SECTIONS HERE : #like pascal, LOL*/
//#define PY_SSIZE_T_CLEAN
#define uchar unsigned char
const int LENGTH = 16;
const int MULS[] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};
const int PI_[] = {252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182};
const int PI_INV_[] = {165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3,
         87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12,
         130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65,
         117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177,
         178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83,
         127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226,
         74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137,
         148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118,
         44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92,
         108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176,
         51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236,
         88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235,
         248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208,
         36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104,
		 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116};

/* FUNCTIONS LIST HERE LIES S #static for it being unaccessible by others */

uchar Keys[][16] = {{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
        {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
        {0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43, 0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44},
        {0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68, 0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04},
        {0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28, 0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac},
        {0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32, 0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b},
        {0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde, 0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1},
        {0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e, 0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84},
        {0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23, 0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17},
        {0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b, 0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43}
        };

typedef struct {
	PyObject_HEAD
	Py_buffer* keys;
	int chopping_flag;
} Crypto;


void printdebug(uchar* arr_ptr){
	printf("FIRST: ");
	for (int i = 0; i < 16; i ++){
		
		printf("%02x", arr_ptr[i]);
	}
	printf("\n");
	printf("SECOND: ");
	for (int i = 16; i < 32; i ++){
		
		printf("%02x", arr_ptr[i]);
	}
	printf("\n");
	printf("THIRD: ");
	for (int i = 32; i < 48; i ++){
		
		printf("%02x", arr_ptr[i]);
	}
	printf("\n");
}

uchar* S(uchar* arr_ptr) {
	for (int i = LENGTH; i < LENGTH + 16; i++){
		arr_ptr[i] = PI_[arr_ptr[i]];
	}
	return arr_ptr;
}

uchar* Sinv(uchar* arr_ptr) {
	for (int i = LENGTH; i < LENGTH + 16; i++){
		arr_ptr[i] = PI_INV_[arr_ptr[i]];
	}
	return arr_ptr;
}

uchar* allocate(int size){
	uchar* fastbuff = (uchar*) malloc (size);
	return fastbuff;
}

uchar* X(uchar* fastbuff, uchar* ptr_strone, int st_idx, uchar* ptr_strtwo, int key_idx){
	/* length should be LENGTH*/
	printf("\nBEFORE XOING\n");
	printdebug(fastbuff);
	for (int idx = 0; idx < LENGTH; idx++){
		fastbuff[idx+16] = ptr_strone[idx+st_idx] ^ ptr_strtwo[idx+key_idx];
		}
	printf("\nXOING\n");
	printdebug(fastbuff);
	return fastbuff;
}

int g_mul(uchar a, uchar b){
	int res = 0;
	int hbit = 0;
	for (int i = 0; i < 8; i++){
		if (b & 1) res ^= a;
		hbit = a & 0x80;
		a <<= 1;
		if (hbit) a ^= 195; // corresponding to give polynom
		b >>= 1;
	}
	return res;

}

int l(uchar* arr_ptr, int st_idx){
	int sum = 0;
	for (int i = 0; i < LENGTH; i++){
		sum ^= g_mul(arr_ptr[st_idx+i], MULS[i]); // modify according to size of arr_ptr
	}
	return sum;
}

void R(uchar* arr_ptr, int st_idx){
	arr_ptr[st_idx-1] = l(arr_ptr, st_idx);
	return;	
}

void Rinv(uchar* arr_ptr, int st_idx){
	arr_ptr[st_idx+16] = arr_ptr[st_idx];
	arr_ptr[st_idx+16] = l(arr_ptr, st_idx+1);
	return;	
}

uchar* L(uchar* arr_ptr){
	for (int st_idx = LENGTH; st_idx > 0; st_idx--){
		R(arr_ptr, st_idx);
	}
	for (int idx = 0; idx < 16; idx++){
		arr_ptr[idx+16] = arr_ptr[idx];
	}
	return arr_ptr;
}

uchar* Linv(uchar* arr_ptr){
	for (int st_idx = 16; st_idx < 32; st_idx++){
		Rinv(arr_ptr, st_idx);
	}
	printf("before assignment ... \n");
	printdebug(arr_ptr);
	for (int idx = 0; idx < 16; idx++){
		arr_ptr[idx+16] = arr_ptr[idx+32];
	}
	printf("before after assignment ... \n");
	printdebug(arr_ptr);
	return arr_ptr;
}

void encrypt(uchar* allocated, uchar* buf, int st_idx, uchar* keys){
	L(S(X(allocated, buf, st_idx, keys, 0)));
	for (int idx = 1; idx < 9; idx++){
		L(S(X(allocated, allocated, 0, keys, idx*16)));
	}
	X(allocated, allocated, 16, keys, 144);
	for (int idx = 0; idx < 16; idx++){
		allocated[idx] = allocated[idx+16];
	}
	return;
}

void decrypt(uchar* allocated, uchar* buf, int st_idx, uchar* keys){
	Sinv(Linv(X(allocated, buf, st_idx, keys, 144)));
	for (int idx = 8; idx > 0; idx--){
		Sinv(Linv(X(allocated, allocated, 16, keys, idx*16)));
	}
	X(allocated, allocated, 16, keys, 0);
	for (int idx = 0; idx < 16; idx++){
		allocated[idx] = allocated[idx+16];
	}
	return;
	
}

/* the Module DocString */
PyDoc_STRVAR(cryptolib__doc__,
	"Cryptolib for galois mul");

/* function doc strings */
PyDoc_STRVAR(encrypt__doc__,
	"str[16], array of iterative keys -> encrypted str[16]");

PyDoc_STRVAR(message_encrypt__doc__,
	"str[any size > 1], array of iterative keys -> encrypted str (with padding)");

PyDoc_STRVAR(message_decrypt__doc__,
	"str[any size > 1], array of iterative keys -> decrypted str (with padding deleted)");

/* {NULL, NULL} means end of definition*/

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
			self->chopping_flag = 0;
		}
		return (PyObject*) self;}

static int
	Crypto_init(Crypto* self, PyObject* args, PyObject *kwds){
		Py_buffer* temp = NULL;
		int tempflag = 0;
		Py_buffer* keysbuf  = (Py_buffer*)malloc(sizeof(Py_buffer));
		if (!PyArg_ParseTuple(args, "y*i", keysbuf, &tempflag))
			return -1;
		
		if (keysbuf){
			if (keysbuf->len != 160){
				free(keysbuf);
				return -1;
			}
			else {
				self->keys = keysbuf;
			}
		}
		if (tempflag) {
			self->chopping_flag = tempflag;
		}
		
		return 0;
}

static PyObject*
	Crypto_name(Crypto *self){
	if (self->keys == NULL){
		PyErr_SetString(PyExc_AttributeError, "keys");
		return NULL;}
	return Py_BuildValue("y#", (uchar*)self->keys->buf, 160);
}

static PyObject*
	Crypto_message_encrypt(Crypto *self, PyObject *args){
		if (self->keys == NULL){
			PyErr_SetString(PyExc_AttributeError, "keys");
			return NULL;
		}
		PyObject* pyMsg;
		Py_buffer* buff = (Py_buffer*)malloc(sizeof(Py_buffer));
		int msg_length = 0;
		if (!PyArg_ParseTuple(args, "y*", buff))
			return NULL;
		msg_length = buff->len / buff->itemsize;
		int extra_length = 0;
		if (msg_length % 16 != 0)
			extra_length = 16 - msg_length % 16;
		int blocks_number = msg_length / 16;
		uchar* retval = allocate((blocks_number + (extra_length!= 0)) * 16);
		uchar* allocated = allocate(48);
		int st_idx = 0;
		for (int jdx = 0; jdx < blocks_number; jdx++){
			encrypt(allocated, (uchar*)buff->buf, jdx * 16, (uchar*)self->keys->buf);
			for (int idx = 0; idx < 16; idx++){
				retval[idx+16*jdx] = allocated[idx];
			}
		}
		if (extra_length){
			for (int idx = 0; idx < 16; idx++){
				if (idx < 16 - extra_length)
					allocated[idx] = ((uchar*)buff->buf)[16*blocks_number+idx];
				else
					allocated[idx] = '\x00';
			}
			encrypt(allocated, allocated, st_idx, (uchar*)self->keys->buf);
			for (int idx = 0; idx < 16; idx++){
				retval[idx+16*blocks_number] = allocated[idx];
			}
				
		}
		pyMsg = Py_BuildValue("y#", retval, (blocks_number + (extra_length!= 0)) * 16);
		free(buff);
		free(retval);
		free(allocated);
		return pyMsg;
}

static PyObject*
	Crypto_message_decrypt(Crypto *self, PyObject *args){
		if (self->keys == NULL){
			PyErr_SetString(PyExc_AttributeError, "keys");
			return NULL;
		}
		PyObject* pyMsg;
		Py_buffer* buff = (Py_buffer*)malloc(sizeof(Py_buffer));
		int msg_length = 0;
		if (!PyArg_ParseTuple(args, "y*", buff))
			return NULL;
		msg_length = buff->len / buff->itemsize;
		if (msg_length % 16 != 0){
			printf("\nWHY WOULD YOU GIVE ME NON-PADDED MESSAGE!\n");
			return NULL;
		}
	    int blocks_number = msg_length / 16;
		printf("got message with %d blocks", blocks_number);
		uchar* retval = allocate(blocks_number * 16);
		uchar* allocated = allocate(48);
		int st_idx = 0;
		for (int jdx = 0; jdx < blocks_number; jdx++){
			decrypt(allocated, (uchar*)buff->buf, jdx * 16, (uchar*)self->keys->buf);
			for (int idx = 0; idx < 16; idx++){
				retval[idx+16*jdx] = allocated[idx];
			}
		}
		// here we insert chopping later on
		int chop_size = 0;
		if (self->chopping_flag){
			int ctr = msg_length - 1;
			while (retval[ctr] == '\0') {
				chop_size += 1;
				ctr -= 1;
			}
		}
		pyMsg = Py_BuildValue("y#", retval, blocks_number * 16 - chop_size);
		free(buff);
		free(retval);
		free(allocated);
		return pyMsg;
}

static PyMethodDef Crypto_methods[] = {
	{"name", (PyCFunction)Crypto_name, METH_NOARGS, "Prints the keys"},
	{"message_encrypt", (PyCFunction)Crypto_message_encrypt, METH_VARARGS, message_encrypt__doc__},
	{"message_decrypt", (PyCFunction)Crypto_message_decrypt, METH_VARARGS, message_decrypt__doc__},
	{NULL} /*sentinel here too*/
};

/* struct moduledef since python3*/
static PyModuleDef cryptolibmodule = {
	PyModuleDef_HEAD_INIT,
        "cryptolib",
        cryptolib__doc__,
        -1,
        NULL, NULL, NULL, NULL, NULL
};
static PyMemberDef Crypto_members[] = {
	{"keys", T_OBJECT_EX, offsetof(Crypto, keys), 0,
	"array of keys"},
	{"chopping_flag", T_INT, offsetof(Crypto, chopping_flag), 0,
	"flag, which decides if we should be chopping result"},
	{NULL} /*sentinel*/
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

