#!/usr/bin/env python2.7
import numpy as np
import math
import random
import time
from PIL import Image
import gmpy2
import fractions

def modinv(a, b):
    ret = None
    if a==1:
        ret = 1
    a = a%b
    v = [[1,0],[0,1]]
    A=b
    B=a
    x = 1
    y = A//B
    C = x*A-y*B
    while C > 1:
        vtmp = [x*v[0][0]-y*v[1][0], x*v[0][1]-y*v[1][1]]
        v = [v[1], vtmp]
        A = B
        B = C
        y = A//B
        C = x*A-y*B
    if C == 1:
        ret = (v[0][1]-y*v[1][1])%b
    return ret

class ElectionBoard():
    voters = []
    n = None
    p = None
    q = None
    lam = None
    g = None
    u = None

    def __init__(self):
        p = 2
        i = random.randint(0, 10)
        j = random.randint(0, 10)
        while p<=1000:
            p = gmpy2.next_prime(p)
        while i > 0:
            p = gmpy2.next_prime(p)
            i = i -1
        q = p+0
        while j > 0:
            q = gmpy2.next_prime(q)
            j = j -1
        n = p*q
        while fractions.gcd((q-1)*(p-1), n) != 1:
            q = gmpy2.next_prime(q)
            n = p*q
        lam = (p-1)*(q-1)/fractions.gcd(p-1,q-1)
        u = None
        g = None
        while u is None:
            g = random.randint(0, n**2)
            u = ((g**lam)%(n**2)-1)//n
            u = modinv(u, n)
        self.n=n
        self.p=p
        self.q=q
        self.lam = lam
        self.g=g
        self.u=u

    def get_voters(self):
        return self.voters

    def register_voter(self, v):
        if v not in self.voters:
            self.voters.append(v)

    def check_registered(self, v):
        return v in self.voters

    def get_public_key(self):
        return (self.n, self.g)
    
    

def main():
    print [1, modinv(1,4), (1,4)]
    print ['n', modinv(2,4), (2,4)]
    print [3, modinv(3,4), (3,4)]
    print [27, modinv(2,53), (2, 53)]
    print [23, modinv(30,53), (30,53)]
    em = ElectionBoard()
    print em.get_public_key()
    print em.get_voters()
    em.register_voter('Sam')
    em.register_voter('Mark')
    em.register_voter('Test')
    print em.get_voters()
    

if __name__ == '__main__':
	main()
