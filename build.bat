python setup.py clean
python setup.py build
python setup.py install
pyinstaller --clean -F -y chclient.py