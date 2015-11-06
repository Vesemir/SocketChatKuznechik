python setup.py clean
python setup.py build
python setup.py install
pyinstaller --clean --onefile -y chclient.py