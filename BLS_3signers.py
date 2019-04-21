from __future__ import absolute_import

from py_ecc.typing import *
from py_ecc.optimized_bn128.optimized_curve import *
from py_ecc.optimized_bn128.optimized_pairing import *
from py_ecc.optimized_bn128.optimized_field_elements import *

import hashlib
import random
import sys
import numpy

def build_poly():
    secret = random.randint(2, 100)
    a1 = random.randint(2, 100)
    a2 = random.randint(2, 100)

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
    print("Lagrange basis polynomial:")
    print(lag_basis)
    return lag_basis

def calculate_lagrange_coeffs(a,b,c,seckeys,L,prime):

    coef2= (seckeys[a-1]*L[0]) % prime
    coef1 = (seckeys[b-1]*L[1]) % prime
    coef0 = (seckeys[c-1] * L[2]) % prime

    lag_coeffs = []
    lag_coeffs.append(coef2)
    lag_coeffs.append(coef1)
    lag_coeffs.append(coef0)
    print("Calculated Lagrange coefficients")
    print(lag_coeffs)
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

def ThresholdSignature(a,b,c,seckeys,message,prime, L) -> Point3D[Field]:
    HM = getHashG1(message)

    sig1 = (seckeys[a-1] * L[0]) % prime
    sig2 = (seckeys[b-1] * L[1]) % prime
    sig3 = (seckeys[c-1] * L[2]) % prime

    sum = (sig1 + sig2 + sig3) % prime
    agg_signature= multiply(HM,sum)
    return agg_signature

def SingleSignature(privkey, message) -> Point3D[Field]:
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

def hashToG1(hashval:int) -> Point3D[Field]:
    x = 0
    y = 0

    hashval = hashval % field_modulus
    if checkHash(hashval):
       # exponent is equal to (field_modulus + 1) / 4
        exponent = 5472060717959818805561601436314318772174077789324455915672259473661306552146

        hashvalcubed = pow(hashval, 3, field_modulus)
        result = (hashvalcubed + 3) % field_modulus

        x = hashval
        y = pow(result, exponent, field_modulus)

        curvepoint = cast(Point3D[FQ], (FQ(x), FQ(y),FQ(1)))

        return curvepoint

    else:

        hashval += 1
        return hashToG1(hashval)
def getHashG1(message) -> Point3D[Field]:
    hashfunc = hashlib.new('sha256')
    hashfunc.update((message).encode('utf-8'))

    hashval = int(hashfunc.hexdigest(), 16)

    return hashToG1(hashval)

def KeyGen(polynomial,prime) :

    seckeys = SecretShares(polynomial,prime)
    print("***************************")
    print("Secret keys of each party")
    print(seckeys)
    print("***************************")
    pubkeys = PubKeys(seckeys)
    print("Public keys of each party")
    print(pubkeys[0])
    print(pubkeys[1])
    print(pubkeys[2])
    print(pubkeys[3])
    print(pubkeys[4])
    print(pubkeys[5])

    return seckeys


def Verify(pubkey,aggregated_signature,Hash) -> bool:


    result = final_exponentiate(pairing(G2, aggregated_signature, final_exponentiate=False, ) * pairing(neg(pubkey), Hash,
                                                                                                        final_exponentiate=False, ))
    return (result == FQ12.one())

poly = build_poly()
seckeys = KeyGen(poly,101)
id1 = random.randint(1, 5)
id2 = random.randint(1, 5)
id3 = random.randint(1, 5)
message = "hello"
print("IDs: " + str(id1) +" "+ str(id2) +" "+str(id3) )
L = lagrange_basis(id1,id2,id3,101)
L_coeffs = calculate_lagrange_coeffs(id1,id2,id3,seckeys,L,101)

aggregated_signature = ThresholdSignature(id1,id2,id3,seckeys,message,101,L)

pubkey = calculate_master_pubkey(poly[2],101)
HM = getHashG1(message)

if Verify(pubkey,aggregated_signature,HM):
    print("Verification successful")

else:
    print('Verification failed')
    print("3 different IDs needed")