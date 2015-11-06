python setup.py clean
python setup.py build
python setup.py install
pyinstaller --clean -y chclient.spec chclient.py