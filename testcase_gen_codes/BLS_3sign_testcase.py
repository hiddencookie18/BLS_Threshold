from __future__ import absolute_import

from py_ecc.bn128.bn128_curve import *
from py_ecc.bn128.bn128_pairing import *
from py_ecc.typing import *

import hashlib
import random
import sys
import numpy

def build_poly():
    secret = random.randint(2, 100000000)
    a1 = random.randint(2, 100000000)
    a2 = random.randint(2, 100000000)

    poly_coeffs = []
    poly_coeffs.append(a2)
    poly_coeffs.append(a1)
    poly_coeffs.append(secret)

    print("polynomial coefficients: ")
    print(poly_coeffs)
    return poly_coeffs

def eval_poly(x,poly,prime):
    result = int((x * x * poly[0] + x * poly[1] + poly[2]) % prime)

    return result

def lagrange_basis(x0,x1,x2,prime):
    coef2 = ((x1 * x0) % prime) * prime_field_inv((((x2-x1)*(x2-x0)) % prime),prime)
    coef1 = ((x0 * x2) % prime) * prime_field_inv((((x1-x0)*(x1-x2)) % prime),prime)
    coef0 = ((x1 * x2) % prime) * prime_field_inv((((x0-x1)*(x0-x2)) % prime),prime)

    lag_basis = []
    lag_basis.append(coef0%prime)
    lag_basis.append(coef1%prime)
    lag_basis.append(coef2%prime)

    return lag_basis

def calculate_lagrange_coeffs(a,b,c,seckeys,L,prime):

    coef2= (seckeys[a-1]*L[0]) % prime
    coef1 = (seckeys[b-1]*L[1]) % prime
    coef0 = (seckeys[c-1] * L[2]) % prime

    lag_coeffs = []
    lag_coeffs.append(coef2)
    lag_coeffs.append(coef1)
    lag_coeffs.append(coef0)

    return lag_coeffs

def SecretShares(poly,prime):
    secretshares = numpy.empty(6)
    for i in range(0, 6):
        secretshares[i] = eval_poly(i+1,poly,prime)

    return secretshares

def PubKeys(seckeys):
    pubkeys = []
    for i in range(0, 6):
        pubkey = (multiply(G2, seckeys[i]))
        pubkeys.append(pubkey)
    return pubkeys

def calculate_master_secret(L,prime):
    master_secret = (L[0] + L[1] +  L[2]) % prime

    return master_secret

def calculate_master_pubkey(master_secret,prime):
    master_pubkey = (multiply(G2, master_secret))

    return master_pubkey

def ThresholdSignature(a,b,c,seckeys,message,prime, L) -> Point2D[Field]:
    HM = getHashG1(message)
    sigma1 = (multiply(HM, seckeys[a - 1] % prime))
    sigma2 = (multiply(HM, seckeys[b - 1] % prime))
    sigma3 = (multiply(HM, seckeys[c - 1] % prime))

    S1 = (multiply(sigma1, L[0] % prime))
    S2 = (multiply(sigma2, L[1] % prime))
    S3 = (multiply(sigma3, L[2] % prime))
    print("Individual signatures:")
    print("Sign 1:" +str(S1))
    print("Sign 2:" +str(S2))
    print("Sign 3:" +str(S3))

    aggregated_signature = add((add(S1, S2)),S3)
    return (aggregated_signature)

def SingleSignature(privkey, message) -> Point2D[Field]:
        HM = getHashG1(message)
        print(is_on_curve(HM, b))

        return (multiply(HM, privkey))

def is_QuadResidue(val:int) -> bool:
    # exponent is equal to (field_modulus - 1) / 2
    val = val % field_modulus
    exponent = 10944121435919637611123202872628637544348155578648911831344518947322613104291

    result = pow(val, exponent, field_modulus)
    if result == 1:
         return True
    else:
        return False

def checkHash(hashval:int) -> bool:
    hashval = hashval % field_modulus

    hashvalcubed = pow(hashval,3,field_modulus)
    result = (hashvalcubed + 3) % field_modulus

    return is_QuadResidue(result)

def hashToG1(hashval:int) -> Point2D[Field]:
    x = 0
    y = 0

    hashval = hashval % field_modulus
    if checkHash(hashval):
       # exponent is equal to (field_modulus + 1) / 4
                 #13680151794899547013904003590785796930342727750260021464811377616609880309761
        exponent = 5472060717959818805561601436314318772174077789324455915672259473661306552146

        hashvalcubed = pow(hashval, 3, field_modulus)
        result = (hashvalcubed + 3) % field_modulus

        x = hashval
        y = pow(result, exponent, field_modulus)

        curvepoint = cast(Point2D[FQ], (FQ(x), FQ(y)))

        return curvepoint

    else:

        hashval += 1
        return hashToG1(hashval)
def getHashG1(message) -> Point2D[Field]:
    hashfunc = hashlib.new('sha256')
    hashfunc.update((message).encode('utf-8'))

    hashval = int(hashfunc.hexdigest(), 16)

    return hashToG1(hashval)

def KeyGen(polynomial,prime) :

    seckeys = SecretShares(polynomial,prime)
    pubkeys = PubKeys(seckeys)


    return seckeys
def prime_field_inv(a: int, n: int) -> int:
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def Verify(pubkey,aggregated_signature,Hash) -> bool:


    result = final_exponentiate(pairing(G2, aggregated_signature, final_exponentiate=False, ) * pairing(neg(pubkey), Hash,
                                                                                                        final_exponentiate=False, ))
    return (result == FQ12.one())

poly = build_poly()
seckeys = KeyGen(poly,curve_order)
id1 = 2
id2 = 3
id3 = 4

message = "hello"
print("IDs: " + str(id1) +" "+ str(id2) +" "+str(id3) )
L = lagrange_basis(id1,id2,id3,curve_order)
pubkeys = PubKeys(seckeys)
L_coeffs = calculate_lagrange_coeffs(id1,id2,id3,seckeys,L,curve_order)

pubkey = calculate_master_pubkey(poly[2],curve_order)
HM = getHashG1(message)

print("*****SAMPLE SUCCESSFUL TEST CASE INPUTS****")
print("IDs: " + str(id1) +" "+ str(id2) +" "+str(id3) )

aggregated_signature = ThresholdSignature(id1,id2,id3,seckeys,message,curve_order,L)


print("Aggregated Signature:")
print(aggregated_signature)
print("Master Public Key:")
print(pubkey)
