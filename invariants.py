from galois import *
""" Инфа:
Итерационные ключи Ki ∈ V128, i = 1, 2, …, 10, вырабатываются на основе ключа
K = k255||…||k0 ∈ V256, ki ∈ V1, i = 0, 1, …, 255, и определяются равенствами:
K1 = k255||…||k128;
K2 = k127||…||k0; (11)
(K2i + 1, K2i + 2) = F [C8(i - 1) + 8]…F [C8(i - 1) + 1](K2i - 1, K2i),
i = 1, 2, 3, 4."""

   
bitstr = '11100101'

assert fi(poly(bitstr)) == bitstr

otherbitstr = '11010100101010101010111010100010'
assert rot_11(otherbitstr) == '01010101011101010001011010100101'
assert vecs(4, 15) == '1111'
assert ints(7, '0001101') == 13
assert ints(10, vecs(10, 798)) == 798
assert X('110', '101') == '011'
assert pi('11101010') == '00100101'
assert convert_poly(convert_int(31)) == 31

assert S(bin(0xffeeddccbbaa99881122334455667700)) == bin(0xb66cd8887d38e8d77765aeea0c9a7efc).zfill(128)
assert S(bin(0xb66cd8887d38e8d77765aeea0c9a7efc)) == bin(0x559d8dd7bd06cbfe7e7b262523280d39).zfill(128)
assert S(bin(0x559d8dd7bd06cbfe7e7b262523280d39)) == bin(0x0c3322fed531e4630d80ef5c5a81c50b).zfill(128)
assert S(bin(0x0c3322fed531e4630d80ef5c5a81c50b)) == bin(0x23ae65633f842d29c5df529c13f5acda).zfill(128)

assert Sinv(S(bin(0xffeeddccbbaa99881122334455667700))) == bin(0xffeeddccbbaa99881122334455667700)
assert Rinv(R(bin(0xffeeddccbbaa99881122334455667700))) == bin(0xffeeddccbbaa99881122334455667700), Rinv(R(bin(0xffeeddccbbaa99881122334455667700)))
assert Linv(L(bin(0xffeeddccbbaa99881122334455667700))) == bin(0xffeeddccbbaa99881122334455667700)
assert R(bin(0x00000000000000000000000000000100)) == bin(0x94000000000000000000000000000001).zfill(128)
assert R(bin(0x94000000000000000000000000000001)) == bin(0xa5940000000000000000000000000000).zfill(128)
assert R(bin(0xa5940000000000000000000000000000)) == bin(0x64a59400000000000000000000000000).zfill(128)
assert R(bin(0x64a59400000000000000000000000000)) == bin(0x0d64a594000000000000000000000000).zfill(128)

assert L(bin(0x64a59400000000000000000000000000)) == bin(0xd456584dd0e3e84cc3166e4b7fa2890d).zfill(128)
assert L(bin(0xd456584dd0e3e84cc3166e4b7fa2890d)) == bin(0x79d26221b87b584cd42fbc4ffea5de9a).zfill(128)
assert L(bin(0x79d26221b87b584cd42fbc4ffea5de9a)) == bin(0x0e93691a0cfc60408b7b68f66b513c13).zfill(128)
assert L(bin(0x0e93691a0cfc60408b7b68f66b513c13)) == bin(0xe6a8094fee0aa204fd97bcb0b44b8580).zfill(128)


K = 0x8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
K1 = bin(0x8899aabbccddeeff0011223344556677).zfill(128)
K2 = bin(0xfedcba98765432100123456789abcdef).zfill(128)
that = bin(K).zfill(128)
assert (K1, K2) == (that[:128], that[128:])
a = bin(0x1122334455667700ffeeddccbbaa9988).zfill(128)
assert X(K1, a) == bin(0x99bb99ff99bb99ffffffffffffffffff)
assert S(X(K1, a)) == bin(0xe87de8b6e87de8b6b6b6b6b6b6b6b6b6)
assert L(S(X(K1, a))) == bin(0xe297b686e355b0a1cf4a2f9249140830)
K = dict()
K[1] = 0x8899aabbccddeeff0011223344556677
K[2] = 0xfedcba98765432100123456789abcdef
K[3] = 0xdb31485315694343228d6aef8cc78c44
K[4] = 0x3d4553d8e9cfec6815ebadc40a9ffd04
K[5] = 0x57646468c44a5e28d3e59246f429f1ac
K[6] = 0xbd079435165c6432b532e82834da581b
K[7] = 0x51e640757e8745de705727265a0098b1
K[8] = 0x5a7925017b9fdd3ed72a91a22286f984
K[9] = 0xbb44e25378c73123a5f32f73cdb6e517
K[10] = 0x72e9dd7416bcf45b755dbaa88e4a4043
thosekeys = compute_keys(K1, K2)
for idx, each in enumerate(thosekeys):
    assert hex(K[idx+1]) == tohex(each)
    if VERBOSITY:
        print(K[idx+1], int(each, 2))

        
assert encrypt(thosekeys, a) == bin(0x7f679d90bebc24305a468d42b9d4edcd).zfill(128)
assert decrypt(thosekeys, encrypt(thosekeys, a)) == a

assert C[1] == bin(0x6ea276726c487ab85d27bd10dd849401).zfill(128)
assert X(C[1], K1) == bin(0xe63bdcc9a09594475d369f2399d1f276).zfill(128)
assert S(X(C[1], K1)) == bin(0x0998ca37a7947aabb78f4a5ae81b748a).zfill(128)
assert L(S(X(C[1], K1))) == bin(0x3d0940999db75d6a9257071d5e6144a6).zfill(128)
assert F(C[1],K1, K2) == (bin(0xc3d5fa01ebe36f7a9374427ad7ca8949).zfill(128),
                          bin(0x8899aabbccddeeff0011223344556677).zfill(128))
assert C[2] == bin(0xdc87ece4d890f4b3ba4eb92079cbeb02).zfill(128)
assert F(C[2], *F(C[1], K1, K2)) == (bin(0x37777748e56453377d5e262d90903f87).zfill(128),
                                    bin(0xc3d5fa01ebe36f7a9374427ad7ca8949).zfill(128))
assert C[3] == bin(0xb2259a96b4d88e0be7690430a44f7f03).zfill(128)
assert F(C[3], *F(C[2], *F(C[1], K1, K2))) == (bin(0xf9eae5f29b2815e31f11ac5d9c29fb01).zfill(128),
                                               bin(0x37777748e56453377d5e262d90903f87).zfill(128))
assert C[4] == bin(0x7bcd1b0b73e32ba5b79cb140f2551504).zfill(128)
assert F(C[4], *F(C[3], *F(C[2], *F(C[1], K1, K2)))) == (bin(0xe980089683d00d4be37dd3434699b98f).zfill(128),
                                                        bin(0xf9eae5f29b2815e31f11ac5d9c29fb01).zfill(128))
assert F(C[5], *F(C[4], *F(C[3], *F(C[2], *F(C[1], K1, K2))))) == (bin(0xb7bd70acea4460714f4ebe13835cf004).zfill(128),
                                                                   bin(0xe980089683d00d4be37dd3434699b98f).zfill(128))
assert F(C[6], *F(C[5], *F(C[4], *F(C[3], *F(C[2], *F(C[1], K1, K2)))))) == (bin(0x1a46ea1cf6ccd236467287df93fdf974).zfill(128),
                                                                             bin(0xb7bd70acea4460714f4ebe13835cf004).zfill(128))
assert F(C[7], *F(C[6], *F(C[5], *F(C[4], *F(C[3], *F(C[2], *F(C[1], K1, K2))))))) == (bin(0x3d4553d8e9cfec6815ebadc40a9ffd04).zfill(128),
                                                                                       bin(0x1a46ea1cf6ccd236467287df93fdf974).zfill(128))
assert F(C[8], *F(C[7], *F(C[6], *F(C[5], *F(C[4], *F(C[3], *F(C[2], *F(C[1], K1, K2)))))))) == (bin(0xdb31485315694343228d6aef8cc78c44).zfill(128),
                                                                                                 bin(0x3d4553d8e9cfec6815ebadc40a9ffd04).zfill(128))
                                                                                 
assert C[5] == bin(0x156f6d791fab511deabb0c502fd18105).zfill(128)
assert C[6] == bin(0xa74af7efab73df160dd208608b9efe06).zfill(128)
assert C[7] == bin(0xc9e8819dc73ba5ae50f5b570561a6a07).zfill(128)
assert C[8] == bin(0xf6593616e6055689adfba18027aa2a08).zfill(128)

