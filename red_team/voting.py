import fractions#added
import random#added
import gmpy2#added

#Read the information about the registered voters(Only requires name at this point)
f = open('voters.txt','r')
line = f.readline()
voters = []
#NOTE: blank lines? beginning/end? extra vote?
#   If the input file contains/ends with empty lines
#    they are considered valid names
#   If you enter your name as "", you can vote again
while line != '':
    voters.append(line.strip())
    line = f.readline()

#Read the candidate information
f = open('candidates.txt','r')
line = f.readline()
candidates = []
while line != '':
    candidates.append(line.strip())
    line = f.readline()

#Total number of voters and candidates
totalN = len(voters)
totalM = len(candidates)

#Function for GCD
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

#Function to calculate modular inverse
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
 
#Function for L   
def L(u):
    return ((u-1)/n)

#Cryptosystem variables
#NOTE: crypto p,q values hardcoded; 
#   we could pretend we didn't know what they are and then bruteforce the ctxt
p = 11
q = 13
n = p*q
l = ((p-1)*(q-1))/2
a = 3
b = 5
g = ((a*n + 1)*(b**n))%(n**2)
u = L((g**l)%(n**2))
u = modinv(u,n)
ek = (n,g)
dk = (l,u)

#Election Board Class
class EM:
    
    #Initiated with decryption key and n
    def __init__(self,dk,n):
        self.dk = dk
        self.n = n
        
    def blindSign(self,m):
        #NOTE: again, constants could be bruteforced
        e = 13
        d = modinv(e,120)
        s = m**d   
        return s
        
    #Function to decrypt a message
    def decrypt(self, c, dk):
        l = dk[0]
        u = dk[1]
        m = L((c**l)%(self.n**2))
        m = (m*u)%self.n
        return m    
    
    #Function to decrypt the votes and announce the winner
    def decryptVotes(self, tableD):
        tie = 0
        winner = 0
        winnernum = 0
        for i in range(len(tableD)):
            dt = self.decrypt(tableD[i],self.dk)
            print candidates[i], "received", dt, "votes"
            if dt > winnernum:
                winner = i
                winnernum = dt
                
        #Checks to see if there is a tie
        for i in range(len(tableD)):
            dt = self.decrypt(tableD[i],self.dk)
            if dt == winnernum:
                tie += 1
        if tie > 1:
            print "No winner there was a tie"
        else:
            print candidates[winner], "is the winner!"                

#Counting Authority class
class CA:
    
    #Initiated with N and M
    def __init__(self,N,M):
        self.totalN = N
        self.totalM = M
        
    #Function to add the encrypted votes given with the table
    def countVotes(self, table):
        tableD = []
        for i in range(self.totalN):
            for j in range(self.totalM):
                if i == 0:
                    tableD.append(table[i][j])
                else:
                    tableD[j] = tableD[j]*table[i][j]   
        return tableD

#Bulletin Board Class
class BB:
    
    #Initiated with voters, number of voters, number of candidates and the encryption key
    def __init__(self,N,M,voters,ek):
        self.voters = voters
        self.totalN = N
        self.totalM = M
        self.ek = ek
        
    #Function for encrypting the vote
    def encrypt(self,m,ek):
        n = ek[0]
        g = ek[1]
        r = 142
        c = ((g**m)*(r**n))%(n**2)
        return c    
    
    #Function to engage in ZKP
    def ZKB(self,m):
        #NOTE: only perform one check? 
        #   Relatively high probability of spoofing this?
        #   Write a proof-of-concept?
        x = 7
        g = self.ek[1]
        r = 17
        s = 13
        e = 0
        u1 = g**r
        u1 = u1*(s**n)
        v = r-(e*m)
        w = s*(x**(-e))
        
        check = g**v
        check = check*(m**e)
        check = check*(w**n)
        return check == u1        
    
    #Function to handle the voting process
    def voting(self):
        e = 13
        table = []
        voted = 0
        voternum = 0        
        
        #Goes until everyone on the list votes
        while voted != self.totalN:
            
            #The only check is your name as of now
            voter = raw_input("Enter your name: ")
            if voter in self.voters:
                #NOTE: process involves entering 0s until you enter a 1 and then stop
                #   subject to a timing attack?
                #NOTE: Can vote for multiple candidates?
                #   As long as you don't vote for candidate[0] you can vote for multiples
                votedyes = False
                voted += 1
                
                #remove the voter to avoid multiple inputs
                voters.remove(voter)
                print "Voter", voter, "enter your vote for:"
                
                #Allows them to vote for each candidate until the vote 1 on someone then it ends
                #for that user
                for j in range(self.totalM):
                    if j == 0:
                        print candidates[j]
                        answer = raw_input('Enter your vote: ')
                        
                        #makes sure that the vote is a 1 or 0
                        while answer != '1' and answer != '0':
                            answer = raw_input('Invalid vote please enter a correct vote: ')
                        answer = int(answer)
                        
                        #Voter sends vote to EM to be signed
                        r = 17      #NOTE: this is pubkey, right?
                        s = answer*(r**e)
                        s2 = EMC2.blindSign(s)
                        sig = s2/r                         
                        
                        #BB checks to make sure that the signature and message match
                        signed = sig**e
                        signed = signed%n
                        if signed != answer:
                            print "Not signed"
                            break
                        
                        #encrypts their answer
                        ct = self.encrypt(answer,self.ek)
                        
                        #engage in ZKB
                        if not(self.ZKB(answer)):
                            print "Failed ZKB"
                            break            
                        
                        #add the vote to the table
                        table.append([ct])
                        if answer == 1:
                            votedyes = True
                    else:
                        
                        #If they voted yes the rest of the votes are no
                        if votedyes == False:
                            print candidates[j]
                            answer = raw_input('Enter your vote: ')
                            while answer != '1' and answer != '0':
                                answer = raw_input('Invalid vote please enter a correct vote: ')
                            answer = int(answer)
                        else:
                            answer = 0
                        ct = self.encrypt(answer,self.ek)
                        table[voted-1].append(ct)
                        
            #if the voter is not in the list the voter is invalid
            else:
                print "Invalid voter"
        return table 

def modinv2(a, b):#added
    #Modular multiplicative inverse
    #Find some `ret` such that `a`*`ret` = 1 mod `b`
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
    
def bruteforce(table):#added
    n2 = n**2
    print 'Real secret key: (lambda, u)=({},{})'.format(l, u)
    pb = 2
    while n%pb != 0:
        pb = gmpy2.next_prime(pb)
    qb = n/pb
    lamfac = ((pb-1)*(qb-1))/fractions.gcd(pb-1, qb-1)
    ubfac = (pow(g,lamfac,n2)-1)//n
    ubfac = modinv2(ubfac, n)
    print '\nSecret key found (by factoring): (lambda, u)=({},{})'.format(lamfac, ubfac)
    table_dec = []
    for row in table:
        row_dec = []
        for m in row:
            c = pow(m,lamfac,n2)
            lc = (c-1)//n
            row_dec.append((lc*ubfac)%n)
        table_dec.append(row_dec)
    print 'Table of decrypted votes (brute forced, factoring method):', table_dec
    m = 0
    lam = 1
    ub = None
    while ub is None:
        ub = (pow(g,lam,n2)-1)//n
        if (fractions.gcd(ub, n)) != 1:
            lam = lam+1
            ub = None
        else:
            ub = modinv2(ub, n)
    while m < n:
        r = random.randint(1, n)
        x = random.randint(1, n)
        while 1!=fractions.gcd(x, n):
            x = random.randint(1, n)
        while 1!=fractions.gcd(r, n):
            r = random.randint(1, n)
        ciphertext = (pow(g,m,n2)*pow(x,n,n2))%n2
        c = pow(ciphertext,lam,n2)
        lc = (c-1)//n
        if m == (lc*ub)%n:
            m = m+1
        else:
            m = 1
            lam = lam+1
            ub = None
            while ub is None:
                ub = (pow(g,lam,n2)-1)//n
                if (fractions.gcd(ub, n)) != 1:
                    lam = lam+1
                    ub = None
                else:
                    ub = modinv2(ub, n)
    print '\nSecret key found (hard method): (lambda, u)=({},{})'.format(lam, ub)
    table_dec = []
    for row in table:
        row_dec = []
        for m in row:
            c = pow(m,lam,n2)
            lc = (c-1)//n
            row_dec.append((lc*ub)%n)
        table_dec.append(row_dec)
    print 'Table of decrypted votes (brute forced, hard method):', table_dec
    print ''
    
def testZKP(bb):#added
    cannotfail = True
    m = 1
    n2 = n**2
    while m < n2:
        if not bb.ZKB(m):
            cannotfail = False
            print m
        m = m+1
    if cannotfail:
        print '\nZKP can never fail'
    elif not cannotfail:
        print '\nZKP can fail and might be working'   
    
if __name__ == "__main__":
    EMC2 = EM(dk,n)
    BB8 = BB(totalN,totalM,voters,ek)
    CIA = CA(totalN,totalM)
    
    table = BB8.voting()
    tableD = CIA.countVotes(table)
    testZKP(BB8)#added
    print '\nTable of encrypted votes: ', table#added
    bruteforce(table)#added
    EMC2.decryptVotes(tableD)
   
