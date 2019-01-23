import sympy as sp

def xgcd(a, b):
    """
    a*x+b*y = gcd(a,b)
    returns: gcd, x, y
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a//b, b, a%b
        x0, x1 = x1, x0-q*x1
        y0, y1 = y1, y0-q*y1
    return  a, x0, y0

def inverse_mod(a, p):
    """
    returns a^-1 mod(p)
    """
    mcd, x, _ = xgcd(a,p)
    if mcd != 1:
        raise Exception('Inverse of {} mod {} doesnt exist'.format(a,p))
    return x % p

def choose_primes(e,k):
    """
    returns p, q primes of 'k' bits, n=p*q has '2k' bits
    gcd(p-1,e) = gcd(q-1,e) = 1
    """
    mcd1, mcd2, p, q = 0, 0, 0, 0
    while mcd1 != 1 or mcd2 != 1 or len(bin(q*p))-2 != k*2:
        p = sp.randprime(2**(k-1),2**k)
        q = sp.randprime(2**(k-1),2**k)
        mcd1, _, _ = xgcd(p-1,e)
        mcd2, _, _ = xgcd(q-1,e)
    return p, q
    
def modexp(a,b,N):
    """
    fast mod exp: a^b mod N
    """
    res = 1
    a = a % N
    while b > 0:
        if b%2 == 1:
            res = (res * a) % N
        a = (a * a) % N
        b = b//2
    return res

class rsa_key:
    def __init__(self, bits_modulo=2048, e=2**16+1):
        """
        generates RSA key (default: n of 2048 bits and public exponent 2**16+1 per defecte)
        """
        p, q = choose_primes(e,bits_modulo//2)
    
        phi = (p-1)*(q-1)
        MCD = sp.gcd(p-1,q-1)
        
        MCM = phi/MCD
        
        d = inverse_mod(e,MCM)
        
        self.publicExponent = e
        self.privateExponent = d
        self.modulus = p*q
        self.primeP = p
        self.primeQ = q
        self.privateExponentModulusPhiP = d % (p-1)
        self.privateExponentModulusPhiQ = d % (q-1)
        self.inverseQModulusP = inverse_mod(q,p)

    def sign(self, message):
        """
        signs message using CRT
        """
        dP = self.privateExponentModulusPhiP
        dQ = self.privateExponentModulusPhiQ
        p = self.primeP
        q = self.primeQ
        qInv = self.inverseQModulusP
        n = self.modulus
        
        m1 = modexp(message,dP,p)
        m2 = modexp(message,dQ,q)
        h = (qInv*((m1-m2) % p)) % p # CRT
        return (m2 + h*q) % n

    def sign_slow(self, message):
        """
        signs message using mod exp
        """
        return modexp(message,self.privateExponent,self.modulus)
        
    def unsign(self, sign):
        return modexp(sign,self.publicExponent,self.modulus)

class rsa_public_key:
    def __init__(self, rsa_key):
        """
        generates public key associated with 'rsa_key'
        """
        self.publicExponent = rsa_key.publicExponent
        self.modulus = rsa_key.modulus

    def verify(self, message, signature):
        """
        check if 'signature' corresponds to 'message'
        """
        return message == modexp(signature,self.publicExponent,self.modulus)
