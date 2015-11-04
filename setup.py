from distutils.core import setup, Extension

setup(name = "cryptoforus", version="0.0", ext_modules=[Extension("cryptolib", ["galois.cpp"])])
