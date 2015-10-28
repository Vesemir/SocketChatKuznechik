import string
from random import choice
from galois import message_encrypt
from galois import message_decrypt
from galois import make_keys
import timeit
import matplotlib.pyplot as plt

choices = '0123456789abcdef'

KEY = '01234567890123456789012345678901'
SIZE = 32
KEYS = make_keys(KEY)

REPEATS = 200


def string_yielder():
    while True:
        yield choice(choices)

def get_string(size=SIZE):
    getter = string_yielder()
    buf = []
    for _ in range(size):
        buf.append(next(getter))
    return ''.join(buf).encode('utf-8')

def avg(numbers):
    return sum(numbers) / len(numbers)

if __name__ == '__main__':
    plotbuff = []
    for strlen in range(1632, 1633, 32):
        tring = get_string(strlen)
        tr = timeit.Timer('message_encrypt(KEYS, tring)', 'from __main__ import KEYS, tring, message_encrypt')
        res = tr.repeat(repeat=REPEATS, number=1)
        print("Timing with block size %d, for %d repeats, got result %f " %(strlen, REPEATS, avg(res)))
        plotbuff.append((strlen, res))
    plt.plot(list(zip(*plotbuff)))
    plt.show()

