#!/usr/bin/env python
import sha256, hmac
import math
from binascii import a2b_hex, b2a_hex

class HKDF(object):
    def __init__(self, ikm, L, salt=None, info="", digestmod = None):
        self.ikm = ikm
        self.keylen = L

        if digestmod is None:
            digestmod = sha256.SHA256

        if callable(digestmod):
            self.digest_cons = digestmod
        else:
            self.digest_cons = lambda d='':digestmod.new(d)
        self.hashlen = len(self.digest_cons().digest())

        if salt is None:
            self.salt = chr(0)*(self.hashlen)
        else:
            self.salt = salt

        self.info = info

    #extract PRK
    def extract(self):
        h = hmac.new(self.salt, self.ikm, self.digest_cons)
        self.prk = h.digest()
        return self.prk

    #expand PRK
    def expand(self):
        N = math.ceil(float(self.keylen)/self.hashlen)
        T = ""
        temp = ""
        i=0x01
        '''while len(T)<2*self.keylen :
            msg = temp
            msg += self.info
            msg += b2a_hex(chr(i))
            h = hmac.new(self.prk, a2b_hex(msg), self.digest_cons)
            temp = b2a_hex(h.digest())
            i += 1
            T += temp
       '''
        while len(T)<self.keylen :
            msg = temp
            msg += self.info
            msg += chr(i)
            h = hmac.new(self.prk, msg, self.digest_cons)
            temp = h.digest()
            i += 1
            T += temp
    
        self.okm = T[0:self.keylen]
        return self.okm

def new(ikm, L, salt=None, info="", digestmod = None):
    return HKDF(ikm, L,salt,info,digestmod)

	
