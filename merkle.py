from random import randint
from math import gcd
import re


class MerkleHellman():
    def find_inverse(self, m, b):  # finde invers of (b) in Galois field (m)
        A = {1: 1, 2: 0, 3: m}
        B = {1: 0, 2: 1, 3: b}
        T = {1: 0, 2: 0, 3: 0}
        Q = 0
        while True:
            if B[3] == 0:
                return A[3]  # no inverses
            if B[3] == 1:
                return B[2]  # B2 = b^-1 mod m
            Q = A[3] // B[3]
            T[1] = (A[1] - (Q * B[1]))
            T[2] = (A[2] - (Q * B[2]))
            T[3] = (A[3] - (Q * B[3]))
            A = B.copy()
            B = T.copy()

    def find_M(self, n):
        for i in range(n, 2, -1):
            if gcd(i, n) == 1:
                return i

    def __init__(self, weights):
        weights.sort()
        self.__bits = len(weights)
        self.__private_keys = weights.copy()
        sum_of_weights = sum(weights)
        self.__N = randint(sum_of_weights, sum_of_weights+100000)
        self.__M = self.find_M(self.__N)

        self.__public_keys = [((pvk*self.__N) % self.__M)
                              for pvk in self.__private_keys]
        self.__invers_N = self.find_inverse(self.__M, self.__N)

    def text_to_bits(self, address=None, encoding='utf-8', errors='surrogatepass'):
        text = open(address, 'r').read()
        bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
        bits = bits.zfill(8 * ((len(bits) + 7) // 8))
        bits = bits.zfill(len(bits)+(self.__bits-(len(bits) % self.__bits)))

        split_bits = [bits[index: index + self.__bits]
                      for index in range(0, len(bits), self.__bits)]

        return split_bits

    def encrypt(self, address):
        cyphs = []
        plain_text = self.text_to_bits(address)

        for i in plain_text:
            sumt = 0
            for t, num in zip(i, self.__public_keys):
                sumt += (int(t)*num)
            cyphs.append(sumt)

        if address:
            name = re.findall(r"(\w+)(\.)", address)[0][0] + "_encrypted"
            file = open(name, "w")
            for i in cyphs:
                file.write(str(i)+',')
            file.close()

        return cyphs

    def decrypt(self, cyphs=[], address=None, encoding='utf-8', errors='surrogatepass'):

        if address:
            cypher_text = open(address, 'r').read().split(',')[:-1]
            cyphs = [int(c) for c in cypher_text]

        codes = ""
        self.__private_keys.reverse()
        for c in cyphs:
            code = (self.__invers_N*c) % self.__M
            stri = ""
            for ms in self.__private_keys:

                if code >= ms:
                    code -= ms
                    stri += '1'
                else:
                    stri += '0'
            codes += stri[::-1]

        n = int(codes, 2)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'
