#include "Python.h"
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
	for (int i=LENGTH; i < LENGTH + 16; i++){
		arr_ptr[i] = PI_[arr_ptr[i]];
	}
	return arr_ptr;
}

uchar* allocate(int size){
	uchar* fastbuff = (uchar*) malloc(48);
	return fastbuff;
}

uchar* X(uchar* fastbuff, uchar* ptr_strone, uchar* ptr_strtwo){
	/* length should be LENGTH*/
	for (int idx = 0; idx < LENGTH; idx++){
		fastbuff[idx+16] = ptr_strone[idx] ^ ptr_strtwo[idx];
		}
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

uchar* L(uchar* arr_ptr){
	for (int st_idx = LENGTH; st_idx > 0; st_idx--){
		R(arr_ptr, st_idx);
	}
	for (int idx = 0; idx < 16; idx++){
		arr_ptr[idx+16] = arr_ptr[idx];
	}
	return arr_ptr;
}

/* the Module DocString */
PyDoc_STRVAR(galois__doc__,
	"Galois polynom multiplication evaluation");



/* function doc strings */
PyDoc_STRVAR(encrypt__doc__,
	"str, array of iterative keys -> encrypted str");

/* wrapper for C function*/
static PyObject *
	py_encrypt(PyObject *self, PyObject *args)
{
	PyObject* pyMsg;
	Py_buffer buff;
	int msg_length = 0;
	int length = 0;
	/* args must have 2 doubles and may have one integer, otherwise max_iterations defaults to 1000*/
	/* :iterate_point is for error messages */
	if (!PyArg_ParseTuple(args, "y*", &buff))
		return NULL;
	/*make sure what we got is correct*/
	msg_length = buff.len / buff.itemsize;
	if (msg_length != 16) return NULL;
	uchar* allocated = allocate(48);
	uchar* temp = L(S(X(allocated, (uchar*)buff.buf, Keys[0])));
	for (int idx = 1; idx < 9; idx++){
		temp = L(S(X(allocated, temp, Keys[idx])));
	}
	temp = X(allocated, temp, Keys[9]);
	for (int idx = 0; idx < 16; idx++){
		temp[idx] = temp[idx+16];
	}
	pyMsg = Py_BuildValue("y#", temp, 16);
	
	free(temp);
	return pyMsg;			
}

/* list of defined methods*/
/* iterate_point is name inside Python*/
/* py_iterate_point is name of c function handling python call*/
/* METH_VARGS tell py how to call the handler*/
/* {NULL, NULL} means end of definition*/
static PyMethodDef galois_methods[] = {
	{"encrypt", py_encrypt, METH_VARARGS, encrypt__doc__},
	{NULL, NULL} /* sentinel*/
};
/* struct moduledef since python3*/
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"galois",
	galois__doc__,
	-1,
	galois_methods,
};
/*PyMODINIT_FUNC helps with portability*/
PyMODINIT_FUNC
	PyInit_galois(void)
{
	return PyModule_Create(&moduledef);
	
}

