#!/usr/bin/env python2.7
import math
import random
import gmpy2
import fractions

def linkboards(em, bb):
    em.set_bulletin_board(bb)
    bb.set_election_board(em)

def modinv(a, b):
    ret = None
    if a==1:
        ret = 1
    a = a%b
    v = [[1,0],[0,1]]
    A=b
    B=a
    y = A//B
    C = (A%B)
    while C > 1:
        vtmp = [(v[0][0]-y*v[1][0]), (v[0][1]-y*v[1][1])]
        v = [v[1], vtmp]
        A = B
        B = C
        y = A//B
        C = (A%B)
    if C == 1:
        ret = (v[0][1]-y*v[1][1])%b
    return ret

class Voter():#always register name with board before creating a new Voter
    name = None
    electionboard = None
    
    def __init__(self, name, em):
        self.name = name
        self.electionboard = em#election board to vote with

    def get_name(self):
        return self.name

    def vote(self, m, candidate):
        em = self.electionboard
        if not em.check_registered(self.name):
            return False
        pubkey = em.get_public_key()
        n = pubkey[0]
        g = pubkey[1]
        n2 = n**2
        print 'Ptext={}'.format(m)
        r = random.randint(1, n)
        x = random.randint(1, n)
        while 1!=fractions.gcd(x, n):
            x = random.randint(1, n)
        while 1!=fractions.gcd(r, n):
            r = random.randint(1, n)
        ciphertext = (pow(g,m,n2)*pow(x,n,n2))%n2
        signedciphertext = (em.blind_sign((ciphertext+r)%n)*modinv(em.blind_sign(r), n2))%n2
        print 'ctext={}'.format(ciphertext)
        print 'signed ctext={}'.format(signedciphertext)
        print 'unsigned ctext={}=?{}%n={}'.format(em.unsign(signedciphertext), ciphertext, ciphertext%n)
        print 'decrypted ctext={}=?{}'.format(em.decrypt(ciphertext), m)
        bb = em.get_bulletin_board()
        numtests = bb.get_num_tests()
        for t in range(numtests):#ZKP
            print 'test {}'.format(t)
            u = n2
            r = random.randint(1, n)
            s = random.randint(1, n)
            while 1!=fractions.gcd(u, n2):
                r = random.randint(1, n)
                s = random.randint(1, n)
                while 1!=fractions.gcd(r, n):
                    r = random.randint(1, n)
                while 1!=fractions.gcd(s, n):
                    s = random.randint(1, n)
                u = (pow(g,r,n2)*pow(s,n,n2))%n2
            print 'getting challenge for {}'.format(u)
            e = bb.generate_challenge(self, u)  
            print 'challenge= {}'.format(e)
            v = r-e*m
            w = 0
            gv = 0
            if v < 0:
                print v
                gv = pow(modinv(g, n2),(0-v),n2) 
                print gv
                w = (s*(pow(modinv(x,n2),e,n2)*pow(modinv(g, n2),((0-v)//n),n2)))%n2
            else:
                print v
                gv = pow(g,v,n2)
                print gv
                w = (s*(pow(modinv(x,n2),e,n2)*pow(g,(v//n),n2)))%n2
                #w = (s*(pow(modinv(x,n2),e,n2)*pow(modinv(g, n2),(v//n),n2)))%n2
            checkval = (gv*pow(ciphertext,e,n2)*pow(w,n,n2))%(n2)
            print 'response= {}'.format(checkval)
            if e is False or not bb.check_response(self, checkval):
                print 'FALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSEFALSE{}'.format(m)
                return False
        return bb.receive_encrypted_message(self, ciphertext, signedciphertext, candidate)

class CountingAuthority():
    electionboard = None

    def __init__(self, em):
        self.electionboard = em

    def send_results(self, votes, numcandidates):
        res = [1 for c in range(numcandidates)]#E(v1)*E(v2)...
        for vote in votes:
            for v in range(len(vote)):
                res[v] = res[v] * vote[v]
        ret = self.electionboard.decrypt_results(res)
        return ret

class BulletinBoard():
    numtests=5#number of times to run ZKP
    electionboard = None
    countingauthority = None
    votes = {}#dict of votes, keyed by votername
    voterdata = {}#stores data used in ZKP to check when necessary
    numcandidates = 1
    
    def __init__(self, nt=5, nc=1):
        self.numtests = nt
        self.numcandidates = nc

    def set_election_board(self, em):
        self.electionboard = em
        self.countingauthority = CountingAuthority(self.electionboard)

    def set_counting_authority(self, ca):
        self.countingauthority = ca

    def get_num_tests(self):
        return self.numtests

    def generate_challenge(self, voter, u):
        votername = voter.get_name()
        if not self.electionboard.check_registered(votername):
            return False
        nt = self.numtests
        if votername in self.voterdata.keys() and self.voterdata[votername][1] > 0:
            nt = self.voterdata[votername][1]
        self.voterdata[votername] = [u, nt]
        n = self.electionboard.get_public_key()[0]
        ret = random.randint(1, n)
        while 1!= fractions.gcd(ret, n) or 1!= fractions.gcd(ret, u):
            ret = random.randint(1, n)
        return ret

    def check_response(self, voter, checkval):
        votername = voter.get_name()
        if self.electionboard.check_registered(votername) and votername in self.voterdata.keys():
            u = self.voterdata[votername][0]
            if u == checkval:
                self.voterdata[votername][1] = self.voterdata[votername][1] - 1
                return True
        return False
    
    def receive_encrypted_message(self, voter, ciphertext, signedciphertext, candidate):
        votername = voter.get_name()
        em = self.electionboard
        n = em.get_public_key()[0]
        unsignedtext = em.unsign(signedciphertext)
        print 'unsigned text = {}=?{}%n=?{}'.format(unsignedtext, ciphertext, ciphertext%n)
        validvote = candidate < self.numcandidates and em.check_registered(votername) and unsignedtext==ciphertext%n
        validvote = validvote and votername in self.voterdata.keys() and self.voterdata[votername][1] <= 0
        if validvote:
            if votername not in self.votes.keys():
                self.votes[votername] = [1 for c in range(self.numcandidates)]
            self.votes[votername][candidate] = ciphertext
            return True 
        return False

    def get_votes(self):
        ret = []
        for v in self.votes.keys():
            ret.append(self.votes[v])
        return ret

    def get_results(self):
        return self.countingauthority.send_results(self.get_votes(), self.numcandidates)

class ElectionBoard():
    voters = []
    #public key:
    n = None    #product of p and q
    g = None    #generator (?)  random integer?

    #initial constants
    p = None
    q = None

    #private key:
    lam = None  # phi(p,q) = (p-1)*(q-1)
    u = None    # 1 / L( g^{lcm} mod {n^2} ), where L(x) = (x-1) / n    ?

    #values for blind sign
    bg = None #blindsignkeydata
    bu = None #blindsignkeydata

    bulletinboard = None

    def __init__(self):#generate keys for PPKE and blindsign
        #generate primes p,q, such that p>q
        #  and (p-1)*(q-1) is coprime with p*q
        p = gmpy2.next_prime(500)
        for _ in range(0, random.randint(0,8)):
            p = gmpy2.next_prime(p)
        q = p
        for _ in range(0, random.randint(1,9)):
            p = gmpy2.next_prime(p)

        n = p*q
        while fractions.gcd((q-1)*(p-1), n) != 1:
            q = gmpy2.next_prime(q)
            n = p*q
        n2 = n**2   # n^2 to be used for modulus
        lam = ((p-1)*(q-1))/fractions.gcd(p-1,q-1)  # least common multiple ?
        u = None
        g = None
        while u is None:
            g = n2
            while 1!= fractions.gcd(g, n2) :
                a = random.randint(1, n)
                b = random.randint(1, n)
                g = ((a*n+1)*pow(b, n, n2))%n2
                #g = random.randint(1, n2)      #why was this changed?
                #   ensure u and n are coprime
            u = (pow(g,lam,n2)-1)//n
            if (fractions.gcd(u, n)) != 1:
                print "This shouldn't happen"
                u = None
            else:
                u = modinv(u, n)
        self.n=n
        self.p=p
        self.q=q
        self.lam = lam
        self.g=g
        self.u=u
        bu = None
        bg = None
        while bu is None or bg == g:
            a = random.randint(1, n)
            b = random.randint(1, n)
            bg = ((a*n+1)*pow(b, n, n2))%n2
            #bg = random.randint(1, n2)
            bu = (pow(bg,lam,n2)-1)//n
            if (fractions.gcd(bu, n)) != 1:
                bu = None
            else:
                bu = modinv(bu, n)
        self.bg=bg  # Generator
        self.bu=bu

    def set_bulletin_board(self, bb):
        self.bulletinboard = bb

    def get_bulletin_board(self):
        return self.bulletinboard

    def get_voters(self):
        return self.voters

    def register_voter(self, v):
        if v not in self.voters:
            self.voters.append(v)
            return True
        return False

    def check_registered(self, v):
        return v in self.voters

    def get_public_key(self):
        return (self.n, self.g)

    def blind_sign(self, message):
        n = self.n
        g = self.bg
        n2 = n**2
        x = random.randint(1, n)
        while 1!= fractions.gcd(x, n):
            x = random.randint(1, n)
        return (pow(g,message,n2)*pow(x,n,n2))%n2

    def unsign(self, message):
        n = self.n
        n2 = n**2
        c = pow(message,self.lam,n2)
        lc = (c-1)//n
        return (lc*self.bu)%n

    def decrypt(self, message): 
        n = self.n
        n2 = n**2
        c = pow(message,self.lam,n2)
        lc = (c-1)//n
        return (lc*self.u)%n

    def decrypt_results(self, tallies): 
        ret = []
        for t in tallies:
            ret.append(self.decrypt(t))
        return ret

    def get_results(self):
        res = self.bulletinboard.get_results()
        maxvotes = 0
        indices = []
        for r in range(len(res)):
            nv = res[r]
            if nv > maxvotes:
                maxvotes = nv
                indices = [r]
            elif nv == maxvotes:
                indices.append(r)
        return [res, indices, maxvotes]#[list of tallies, list of indices of winner(s), votes winner(s) got]

def main():
    print [1, modinv(1,4), (1,4)]
    print ['n', modinv(2,4), (2,4)]
    print [3, modinv(3,4), (3,4)]
    print [27, modinv(2,53), (2, 53)]
    print [23, modinv(30,53), (30,53)]
    em = ElectionBoard()
    k = em.get_public_key()
    n = k[0]
    n2 = n**2
    print k
    print em.get_voters()
    em.register_voter('Sam')
    em.register_voter('Mark')
    em.register_voter('Test')
    print em.get_voters()
    sam = Voter('Sam', em)
    mark = Voter('Mark', em)
    test = Voter('Test', em)
    bb = BulletinBoard(15, 10)
    linkboards(em, bb)
    numfails = 0
    numhmfails = 0
    for i in range(0, 1000):
        s = em.blind_sign(i)
        u = em.unsign(s)
        if u != i:
            print ['FAIL', i, s, u]
            numfails = numfails +1
        for j in range(i,1000):
            t = em.blind_sign(j)
            u = em.blind_sign(i+j)
            if em.unsign(((s*t)%n2))!=((i+j)%n):
                print ['NOT HOMOMORPHIC', i, j, s,t, u]
                numhmfails = numhmfails+1
    print numfails, numfails*1.0/10
    print numhmfails, numhmfails*1.0/10000
    return
    print sam.vote(0,0)
    print sam.vote(0,1)
    print sam.vote(0,2)
    print sam.vote(0,3)
    print sam.vote(1,4)
    print sam.vote(1,5)
    print sam.vote(0,6)
    print sam.vote(1,7)
    print sam.vote(0,8)
    print sam.vote(1,9)
    print sam.vote(1,6)
    print sam.vote(1,6)
    print em.get_results()

if __name__ == '__main__':
	main()
