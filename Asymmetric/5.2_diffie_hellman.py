from random import randint

prime = 23
primitiveRoot = 9

BobPrivate = randint(1, prime - 1)
AlicePrivate = randint(1, prime - 1)

BobPublic = pow(primitiveRoot, BobPrivate, prime)
AlicePublic = pow(primitiveRoot, AlicePrivate, prime)

sharedSecredBob = pow(AlicePublic, BobPrivate, prime)
sharedSecredAlice = pow(BobPublic, AlicePrivate, prime)

if (sharedSecredAlice == sharedSecredBob):
    print("successfully computed")
    print("bob secret: ", BobPrivate)
    print("bob public: ", BobPublic)
    print("alice secret: ", AlicePrivate)
    print("alice public: ", AlicePublic)
    print("bob shared: ", sharedSecredBob)
    print("alice shared: ", sharedSecredAlice)
else:
    print("does not match")