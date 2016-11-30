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
        if not em.check_registered(self):
            print 'You are not a registered voter'
            return False
        pubkey = em.get_public_key()
        n = pubkey[0]
        g = pubkey[1]
        n2 = n**2
        r = random.randint(1, n)
        x = random.randint(1, n)
        while 1!=fractions.gcd(x, n):
            x = random.randint(1, n)
        while 1!=fractions.gcd(r, n):
            r = random.randint(1, n)
        ciphertext = (pow(g,m,n2)*pow(x,n,n2))%n2
        signedciphertext = (em.blind_sign((ciphertext*em.unsign(r))%n, self)*modinv(r, n))%n
        bb = em.get_bulletin_board()
        numtests = bb.get_num_tests()
        for t in range(numtests):#ZKP
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
            e = bb.generate_challenge(self, u)  
            if e is False:
                print 'No challenge issued for ZKP from the bulletin board, vote dismissed'
                return False
            v = r-e*m
            w = 0
            if v < 0:
                w = (s*(pow(modinv(x,n2),e,n2)*pow(modinv(g, n2),((0-v)//n),n2)))%n2
            else:
                w = (s*(pow(modinv(x,n2),e,n2)*pow(g,(v//n),n2)))%n2
            if not bb.check_response(self, ciphertext, v, w):
                print 'Your vote failed the ZKP proof'
                return False
        return bb.receive_encrypted_message(self, ciphertext, signedciphertext, candidate)

class CountingAuthority():
    electionboard = None

    def __init__(self, em):
        self.electionboard = em

    def check_results(self, vote):
        res = 1
        for v in vote:
            res = res * v
        return 1==self.electionboard.decrypt(res)

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
        if not self.electionboard.check_registered(voter):
            print 'You are not a registered voter'
            return False
        nt = self.numtests
        nc = self.numcandidates
        if votername in self.voterdata.keys():
            nc = self.voterdata[votername][3]
            if self.voterdata[votername][1] > 0:
                nt = self.voterdata[votername][1]
        n = self.electionboard.get_public_key()[0]
        ret = random.randint(1, n)
        while 1!= fractions.gcd(ret, n) or 1!= fractions.gcd(ret, u):
            ret = random.randint(1, n)
        self.voterdata[votername] = [u, nt, ret, nc]
        return ret

    def check_response(self, voter, ciphertext, v, w):
        votername = voter.get_name()
        if self.electionboard.check_registered(voter) and votername in self.voterdata.keys():
            u = self.voterdata[votername][0]
            e = self.voterdata[votername][2]
            k = self.electionboard.get_public_key()
            n = k[0]
            g = k[1]
            n2 = n**2
            gv = 0
            if v < 0:
                gv = pow(modinv(g, n2),(0-v),n2) 
            else:
                gv = pow(g,v,n2)
            checkval = (gv*pow(ciphertext,e,n2)*pow(w,n,n2))%(n2)
            if u == checkval:
                self.voterdata[votername][1] = self.voterdata[votername][1] - 1
                return True
            else:
                self.voterdata[votername][1] = self.numtests
        return False
    
    def receive_encrypted_message(self, voter, ciphertext, signedciphertext, candidate):
        votername = voter.get_name()
        em = self.electionboard
        n = em.get_public_key()[0]
        unsignedtext = em.unsign(signedciphertext)
        validvote = candidate < self.numcandidates and em.check_registered(voter) and unsignedtext==ciphertext%n
        validvote = validvote and votername in self.voterdata.keys() and self.voterdata[votername][1] <= 0
        if validvote:
            if votername not in self.votes.keys():
                self.votes[votername] = [1 for c in range(self.numcandidates)]
            if self.voterdata[votername][3]> 0 and self.votes[votername][candidate] == 1:
                self.votes[votername][candidate] = ciphertext
                self.voterdata[votername][3] = self.voterdata[votername][3] - 1
                if self.voterdata[votername][3] <= 0:
                    if not self.check_if_voted(voter):
                        self.votes.pop(votername, None)
                        self.voterdata.pop(votername, None)
                        print 'Your vote is invalid- it does not sum to 1, and has now been thrown out'
                        return False
                return True 
        print 'Your vote is invalid- Either you are unregistered, your vote does not have a valid signature, or you did not prove ZKP'
        print self.voterdata[votername]
        return False

    def check_if_voted(self, voter):
        votername = voter.get_name()
        if votername in self.votes.keys():
            return self.countingauthority.check_results(self.votes[votername])
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
    be = None #blindsignkeydata
    bd = None #blindsignkeydata

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
        lam = ((p-1)*(q-1))
        be = random.randint(1, lam)
        bd = modinv(be, lam)
        while 1!=fractions.gcd(be, lam) or bd is None:
            be = random.randint(1, lam)
            bd = modinv(be, lam)
        lam = lam/fractions.gcd(p-1,q-1)  # least common multiple ?
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
        self.be=be
        self.bd=bd

    def set_bulletin_board(self, bb):
        self.bulletinboard = bb

    def get_bulletin_board(self):
        return self.bulletinboard

    def get_voters(self):
        return self.voters

    def register_voter(self, v):
        if v not in self.voters and v.get_name() not in [voter.get_name() for voter in self.voters]:
            self.voters.append(v)
            return True
        return False

    def check_registered(self, v):
        return v in self.voters

    def get_public_key(self):
        return (self.n, self.g)

    def blind_sign(self, message, voter):
        if voter not in self.voters:
            return False
        n = self.n
        e = self.be
        return pow(message,e,n)

    def unsign(self, message):
        n = self.n
        d = self.bd
        return pow(message,d,n)

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

    def check_if_voted(self, voter):
        return self.bulletinboard.check_if_voted(voter)

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
    em = ElectionBoard()
    candidates = range(0,5)
    numcandidates = len(candidates)
    bb = BulletinBoard(15, numcandidates)
    linkboards(em, bb)
    v = 0
    voters = {}
    while v < 10:
        vname =  raw_input('{}What is your name?\n'.format(v))
        voter = Voter(vname, em)
        if vname in voters.keys():
            voter = voters[vname]
        else:
            voters[vname] = voter
        em.register_voter(voter)
        if em.check_if_voted(voter):
            print 'A voter with this name has already voted'
            v = v - 1
        else:
            c = 0
            while c < numcandidates:
                vote = int(raw_input('What is your vote for candidate {} (Enter 0 for no or 1 for yes)?\n'.format(candidates[c])))
                if not voter.vote(vote, c):
                    restart =  raw_input('Start your vote over (y/n)?')
                    if restart == 'y':
                        c = -1
                    else:
                        restart =  raw_input('Quit voting (y/n)?')
                        if restart == 'y':
                            c = numcandidates
                            v = v-1
                        else:
                            c = c-1
                c = c+1
        v = v+1
    print em.get_results()

if __name__ == '__main__':
	main()
