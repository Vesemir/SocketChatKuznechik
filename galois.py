import binascii
from itertools import chain
from functools import reduce
from operator import xor

VERBOSITY = False
FAST = True

PI_ = (252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
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
116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182)

PIINV = (165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3,
         87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12,
         130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65,
         117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177,
         178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83,
         127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226,
         74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137,
         148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118,
         44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92,
         108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176,
         51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236,
         88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235,
         248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208,
         36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104,
         245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116)


usualbin = bin

def bin(num):
    return usualbin(num)[2:]


class mem:
    """Инстанс данного класса представляет собой элемент, поддерживающий операцию
возведения в степень"""
    def __init__(self, power):
        self.pow = power

    def __mul__(self, other):
        assert isinstance(other, mem)
        res = mem(self.pow + other.pow)
        return res

    def __str__(self):
        if self.pow == 0:
            return '1'
        if self.pow == 1:
            return 'x'
        return 'x ^ {}'.format(self.pow)


class Polynom_GF_2:
    """Имплементит умножение полиномов надо конечным полем GF(2)"""
    def __init__(self, members, diviser=None):
        self.members = sorted([each for each in members],
                              key=lambda x: x.pow,
                              reverse=True)
        if members != []:
            self.pow = max((member for member in self.members),
                           key=lambda x: x.pow).pow
        else:
            self.pow = 7
        
        self.diviser = diviser
        self.size = len(self.members)

    def __sub__(self, other):
        whole = [each for each in self]
        for each in reversed(whole):
            if each.pow == other.pow:
                self.members.remove(each)
        return self

    def vectorize(self):
        return ''.join(['1' if mem(idx) in self else '0'
                       for idx in range(self.pow, -1, -1)])

    def __hash__(self):
        whole = 0
        for each in self:
            whole += id(each.pow) ** 3
        return whole

    def __eq__(self, other):
        return all(each in self for each in other)

    def compute(self):
        return sum([2 ** each.pow for each in self])

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        return (each for each in self.members)

    def __str__(self):
        modulo = ''
        if self.diviser is not None:
            modulo = '\nmodulo: %s' % str(self.diviser)
        return ' + '.join(str(member) for member in self.members) + modulo

    def __contains__(self, other):
        return any(member.pow == other.pow for member in self.members)

    def count(self, n):
        num = 0
        for each in self:
            
            if each.pow == n.pow:
                num += 1
        return num

    def __truediv__(self, other):
        tempres = []
        for ourmember in self.members:
            if ourmember not in other:
                tempres.append(ourmember)
        for theirmember in other.members:
            if theirmember not in self:
                tempres.append(theirmember)
        res = Polynom_GF_2(tempres)
        return res

    def __add__(self, other): #wow so fast
        hother = other
        sobad = self.compute()
        other = other.compute()
        tempres = sobad ^ other
        
        res = Polynom_GF_2(convert_int(tempres), diviser=self.diviser)
        return res

    def __rmul__(self, other):
        return self.__mul__(other)
    
    def __mul__(self, other): # trying faster implementation
        hother = other
        if isinstance(other, Polynom_GF_2):
             other = other.compute()
                    
        sobad = self.compute()
        modulo = 2 ** self.diviser.pow
        remnant = self.diviser.compute() % modulo
        
        tempres = 0
        for dummy in range(8):
            if other & 1:
                tempres ^= sobad
            hbit = sobad & 0x80
            sobad <<= 1
            sobad %= modulo# lol implementation sucks
            if hbit:
                sobad ^= remnant
            other >>= 1
        
        res = Polynom_GF_2(convert_int(tempres), diviser=self.diviser)
      
        return res

CANONIC_POLY = Polynom_GF_2((mem(8), mem(7), mem(6), mem(1), mem(0)))

def intpoly(val):
    return INTDICT.get(val)


def convert_int(val):
    if val == 0:
        if VERBOSITY:
            print("INT 0 -> ZERO POLYNOM")
        return Polynom_GF_2([])
    binstr = bin(val).zfill(8)
        
    res = Polynom_GF_2((mem(idx) for idx, bit in enumerate(reversed(binstr)) if int(bit)))
    if VERBOSITY:
        print("INT {} -> POLYNOM {}".format(val, res))
    return res


def getdict(poly=CANONIC_POLY):
    di = dict()
    this = Polynom_GF_2([mem(1)],
                        diviser=poly)
    multiplier = Polynom_GF_2([mem(1)])
    for idx in range(255):
        di[idx] = this
        this = this * multiplier
    return di


#INTDICT = getdict()
#for key, value in INTDICT.items():
#    print("POWER : {}\nMEMBER: {} COUNTED: {}".format(key + 1, value, value.compute()))



def convert_poly(poly):
    return poly.compute()


def fi(poly):
    return ''.join('1' if mem(idx) in poly else '0'
                    for idx in range(poly.pow, -1, -1)).zfill(8)


def poly(bitstr):
    return Polynom_GF_2((mem(idx) for idx, bit in
                         enumerate(reversed(bitstr)) if int(bit)),
                        diviser=CANONIC_POLY)


def add_32(one, other):
    return (one + other) % 2 ** 32


def vecs(s, elem):
    return bin(elem).zfill(s)


def ints(s, bitstr):
    res = int(bitstr, 2)
    return res


def rot_11(bitstr):
    return bitstr[11:] + bitstr[:11]


def arr_gen(gen):
    return list(chain((0 for _ in range(16)), gen, (0 for _ in range(16))))

#print("DOOM: ", arr_gen((3 for doom in range(1))))

def X(str_a, str_b):
    assert len(str_a) == len(str_b)
    if len(str_a) == 16:
        return arr_gen(a ^ str_b[idx] for idx, a in enumerate(str_a))
    else:
        return [a ^ str_b[idx] for idx, a in enumerate(str_a)]


def S(bt_ptr):
    for idx, bt in enumerate(bt_ptr[16:32]):
        bt_ptr[16+idx] = PI_[bt]
    return bt_ptr



#print(S(X([0, 5, 3, 4, 3, 6, 7, 8, 6, 9, 34, 43, 2, 32, 43, 65],
#          [3, 1, 8, 54, 12, 23, 43, 29, 4, 6, 7 ,5 ,34, 21, 43, 21])))

def Sinv(bitstr):
    for idx, bt in enumerate(bt_ptr[16:32]):
        bt_ptr[16+idx] = PIINV[bt]
    return bt_ptr

# no strings allowed
def g_mul(one, other, divpow=8, modulo=256, remnant=195):
    res = 0
    for dummy in range(8):
        if other & 1:
            res ^= one
        hbit = one & 0x80
        one <<= 1
        one %= modulo# lol implementation sucks
        if hbit:
            one ^= remnant
        other >>= 1
    return res

MULS = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
    
def l_nonverbose(arr_ptr, st_idx):
    assert len(arr_ptr) == 48
    return reduce(xor, map(g_mul, *(MULS, arr_ptr[st_idx:st_idx+16])))


def l(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15):
    return fi(148 * poly(a15) + 32 * poly(a14) + 133 * poly(a13) + 16 * poly(a12) + \
              194 * poly(a11) + 192 * poly(a10) + 1 * poly(a9) + 251 * poly(a8) +\
              1 * poly(a7) + 192 * poly(a6) + 194 * poly(a5) + 16 * poly(a4) +\
              133 * poly(a3) + 32 * poly(a2) + 148 * poly(a1) + 1 * poly(a0))
if FAST:
    l = l_nonverbose

def R(arr_ptr, st_idx):
    arr_ptr[st_idx-1] = l(arr_ptr, st_idx)
    return arr_ptr


def Rinv(arr_ptr, st_idx):
    arr_ptr[st_idx+16] = l(arr_ptr, st_idx)
    return res


def L(bitstr):
    for st_idx in reversed(range(1, 17)):
        bitstr = R(bitstr, st_idx)
    return arr_gen(bitstr[:16])


def Linv(bitstr):
    for st_idx in range(16, 32):
        bitstr = Rinv(bitstr, st_idx)
    return arr_gen(bitstr[32:])


def bytize(vec):
    assert len(vec) == 128
    bts = []
    for idx in range(len(vec) // 8):
        partial = vec[idx*8:(idx+1)*8]
        bts.append(int(partial, 2))
    return arr_gen(bts)



F = lambda gamma, a1, a0: (X(L(S(X(gamma, a1))), a0), a1)


Cmake = lambda i: L(bytize(vecs(128, i)))

tohex = lambda b: ''.join(hex(each)[2:].zfill(2) for each in b)

C = dict()

for idx in range(1, 33):
    C[idx] = arr_gen(Cmake(idx)[16:32])
        
def k_k_and_1(k_, k__, mul):
    roundkeys = k_, k__
    
    for idx in range(1 + mul * 8, 9 + mul * 8):
        roundkeys = F(C[idx], *roundkeys)
        
    return roundkeys

def compute_keys(k1, k2):
    keymas = []
    keymas.extend([k1, k2])
    ki, kj = k1, k2
    for stdeg in range(4):
        ki, kj = k_k_and_1(ki, kj, stdeg)
        keymas.extend([ki, kj])
    return keymas


K1 = bin(0x8899aabbccddeeff0011223344556677).zfill(128)
K2 = bin(0xfedcba98765432100123456789abcdef).zfill(128)

thosekeys = compute_keys(bytize(K1), bytize(K2))




def encrypt(keys, message):
    temp = L(S(X(keys[0], message)))
    for idx in range(1, 9):
        temp = L(S(X(keys[idx], temp)))
    res = X(keys[9], temp)
    if VERBOSITY:
        print("ENC({}) = {}".format(message, res))
    return res


def make_keys(key):
    rawkey = bin(int(binascii.hexlify(key.encode('utf-8')), 16)).zfill(256)
    K1, K2 = rawkey[:128], rawkey[128:]
    return compute_keys(K1, K2)
    
chop = lambda s: s[32:64]

def message_encrypt(keys, message):
    '''message - hexed bytes themselves, so...'''
    res = []
    extralength = (32 - (len(message) % 32)) * b'0'
    rawmessage = message + extralength
       
    for idx in range(len(rawmessage) // 32):
        partial = rawmessage[idx*32:(idx+1)*32]
        res.append(chop(tohex(encrypt(keys, bytize(bin(int(partial, 16)))))))
        
    return ''.join(res).encode('utf-8')


def message_decrypt(keys, message):
    res = []
    
    for idx in range(len(message) // 32):
        partial = message[idx*32:(idx+1)*32]
        res.append(decrypt(keys, bin(int(partial, 16)).zfill(128)))
    decrypted = ''.join(res)
    
    morphed = hex(int(decrypted, 2))[2:]
    
    chopping = 0
    for idx in reversed(range(len(morphed) // 2)):
        candy = morphed[idx*2:(idx+1)*2]
        if candy == '00':
            chopping += 1
    if chopping:
        morphed = morphed[:-2*chopping]
    
    return morphed


def decrypt(keys, crypto):
    temp = Sinv(Linv(X(keys[9], crypto)))
    for idx in range(8, 0, -1):
        temp = Sinv(Linv(X(keys[idx], temp)))
    res = X(keys[0], temp)
    if VERBOSITY:
        print("DEC({}) = {}".format(crypto, res))
    return res


if VERBOSITY:
    print("Done computating cmake")

def sanity_check():
    import invariants

# sanity_check()
