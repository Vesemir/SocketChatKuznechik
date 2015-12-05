from distutils.core import setup, Extension

setup(name = "cryptoforus",
      version="0.1",
      description="Too much hassle, but at least it works now",
      author_email="shackaler@yandex.ru",      
      ext_modules=[Extension("cryptolib",
                             ["galois.cpp"]
                             ,extra_compile_args=['/O2']
                             )
                   ]
      )
