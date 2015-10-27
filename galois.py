import binascii

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


def X(str_a, str_b):
    return bin(int(str_a, 2) ^ int(str_b, 2)).zfill(len(str_a))


def pi(bitstr):
    return vecs(8, PI_[ints(8, bitstr)])


def piinv(bitstr):
    return vecs(8, PIINV[ints(8, bitstr)])


def S(bitstr):
    if not len(bitstr) == 128:
        bitstr = bitstr.zfill(128)
    res = []
    for idx in range(len(bitstr) // 8):
        res.append(pi(bitstr[idx*8:(idx+1)*8]))
    return ''.join(res)


def Sinv(bitstr):
    if not len(bitstr) == 128:
        bitstr = bitstr.zfill(128)
    res = []
    for idx in range(len(bitstr) // 8):
        res.append(piinv(bitstr[idx*8:(idx+1)*8]))
    return ''.join(res)

def g_sum(*args):
    wh = args[0]
    for arg in args[1:]:
        wh = wh ^ arg
    return wh

def g_mul(one, other, divpow=8, modulo=256, remnant=195):
    other = int(other, 2)
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
    
def l_nonverbose(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15):
    return bin(g_sum(g_mul(148, a15), g_mul(32, a14), g_mul(133, a13), g_mul(16, a12),
                    g_mul(194, a11), g_mul(192, a10), g_mul(1, a9), g_mul(251, a8),
                    g_mul(1, a7), g_mul(192, a6), g_mul(194, a5), g_mul(16, a4),
                    g_mul(133, a3), g_mul(32, a2), g_mul(148, a1), g_mul(1, a0))).zfill(8)


def l(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15):
    return fi(148 * poly(a15) + 32 * poly(a14) + 133 * poly(a13) + 16 * poly(a12) + \
              194 * poly(a11) + 192 * poly(a10) + 1 * poly(a9) + 251 * poly(a8) +\
              1 * poly(a7) + 192 * poly(a6) + 194 * poly(a5) + 16 * poly(a4) +\
              133 * poly(a3) + 32 * poly(a2) + 148 * poly(a1) + 1 * poly(a0))
if FAST:
    l = l_nonverbose

def R(bitstr):
    if not len(bitstr) == 128:
        bitstr = bitstr.zfill(128)
    argarray = dict()
    for idx in range(len(bitstr) // 8):
        part = bitstr[idx*8:(idx+1)*8]
        argarray['a%d'%(15-idx)] = part
    res = l(**argarray) + ''.join(argarray['a%d'%idx] for idx in range(15, 0, -1))
    return res


def Rinv(bitstr):
    if not len(bitstr) == 128:
        bitstr = bitstr.zfill(128)
    argarray = dict()
    
    for idx in range(len(bitstr) // 8):
        part = bitstr[idx*8:(idx+1)*8]
        argarray[15-idx] = part
    shiftedarray = [argarray[idx] for idx in range(16)]
    shiftedarray = shiftedarray[15:] + shiftedarray[:15]
    res = ''.join(argarray[idx] for idx in range(14, -1, -1)) + l(*shiftedarray)
    return res


def L(bitstr):
    for dummy in range(16):
        bitstr = R(bitstr)
    return bitstr


def Linv(bitstr):
    if not len(bitstr) == 128:
        bitstr = bitstr.zfill(128)
    res = bitstr
    
    for dummy in range(16):
        res = Rinv(res)
        assert len(res) == 128
    return res


F = lambda gamma, a1, a0: (X(L(S(X(gamma, a1))), a0), a1)


Cmake = lambda i: L(vecs(128, i))
C = dict()

for idx in range(1, 33):
    C[idx] = Cmake(idx)

    
def k_k_and_1(k_, k__, mul):
    roundkeys = k_, k__
    for idx in range(1 + mul * 8, 9 + mul * 8):
        roundkeys = F(C[idx], *roundkeys)
    return [each.zfill(128) for each in roundkeys]

tohex = lambda b: hex(int(b, 2))

def compute_keys(k1, k2):
    keymas = []
    keymas.extend([k1, k2])
    ki, kj = k1, k2
    for stdeg in range(4):
        ki, kj = k_k_and_1(ki, kj, stdeg)
        keymas.extend([ki, kj])
    return keymas


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
    


def message_encrypt(keys, message):
    res = []

    extralength = (32 - (len(message) % 32)) * b'0'
    rawmessage = message + extralength
       
    for idx in range(len(rawmessage) // 32):
        partial = rawmessage[idx*32:(idx+1)*32]
        res.append(encrypt(keys, bin(int(partial, 16)).zfill(128)))
        
    return hex(int(''.join(res), 2))[2:].encode('utf-8')


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
