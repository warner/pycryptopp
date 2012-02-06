#!/usr/bin/env python

import random, re, time
import unittest
import hashlib

from binascii import a2b_hex, b2a_hex
from pycryptopp.hash import hkdf, sha256

def randstr(n):
	return ''.join(map(chr, map(random.randrange, [0]*n, [256]*n)))

def HKDF_Bench1():
    print "HKDF_Bench1 starting\n"
    ctxinfo = "hkdf bench test"
    salt = ""
    hash = sha256.SHA256
    l = 20
#    hk = hkdf.new(ikm, l, salt, ctxinfo, hash)
    start_time = time.clock()
    for times in xrange(1000):
        ikm = randstr(100)
	hk = hkdf.new(ikm, l, salt, ctxinfo, hash)
	prk = hk.extract()
	okm = hk.expand()

    stop_time = time.clock()
    print "hkdf using a 100 bytes ikm without salt, test 1000 times, Bench1: ", stop_time-start_time, "sec \n"
    print "HKDF_Bench1 ending\n\n"

def HKDF_Bench2():
    print "HKDF_Bench2 starting\n"
    ctxinfo = "hkdf bench test"
    hash = sha256.SHA256
    l = 20
    salt = ""
    start_time = time.clock()
    for times in xrange(1000):
        ikm = randstr(1000)
        hk = hkdf.new(ikm, l, salt, ctxinfo, hash)
	prk = hk.extract()
	okm = hk.expand()

    stop_time = time.clock()
    print "hkdf using a 1000 bytes ikm without salt, test 1000 times, Bench2: ",stop_time-start_time, "sec \n"
    print "HKDF_Bench2 ending\n\n"

def HKDF_Bench3():
    print "HKDF_Bench3 starting\n"
    ctxinfo = "hkdf bench test"
    hash = sha256.SHA256
    l = 20
    start_time = time.clock()
    for times in xrange(1000):
        ikm = randstr(100)
	salt = randstr(64)
	hk = hkdf.new(ikm, l, salt, ctxinfo, hash)
	prk = hk.extract()
	okm = hk.expand()

    stop_time = time.clock()
    print "hkdf using a 100 bytes ikm with 64 bytes salt, test 1000 times, Bench3: ", stop_time-start_time, "sec \n"
    print "HKDF_Bench3 ending\n\n"

def main():
    HKDF_Bench1()
    HKDF_Bench2()
    HKDF_Bench3()

if __name__ == "__main__":
    main()


    
