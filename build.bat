set PYTHONx86=C:\Python34_x86\python.exe
set PYINSTx86=C:\Python34_x86\Scripts\pyinstaller.exe
%PYTHONx86% setup.py clean
%PYTHONx86% setup.py build
%PYTHONx86% setup.py install
%PYINSTx86% --onefile -y chclient.py