from distutils.core import setup, Extension

setup(name = "galois", version="0.0", ext_modules=[Extension("galois", ["galois.cpp"])])
