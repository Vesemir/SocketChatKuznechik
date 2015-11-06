from galois import make_keys
from cryptolib import Crypto
from binascii import unhexlify as uh
from binascii import hexlify as hx
cryptor = Crypto(make_keys(uh(b'8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')), 0)
one = cryptor.message_encrypt(uh(b'1122334455667700ffeeddccbbaa9988'))
two = uh(b'7f679d90bebc24305a468d42b9d4edcd')
print(one)
print(two)
assert one == two
print('%r == %r' % (one, two))
