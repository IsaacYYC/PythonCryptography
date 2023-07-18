from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_signature(privateKey, plaintext):

    ECCPrivateKey = ECC.import_key(privateKey)
    sha256Hash = SHA256.new(plaintext)
    digitalSignature = DSS.new(ECCPrivateKey, "fips-186-3").sign(sha256Hash)
    return digitalSignature

def verify_signature(publicKey, plaintext, digitalSignature):
    
    ECCPublicKey = ECC.import_key(publicKey)
    verificationSHA256Hash =  SHA256.new(plaintext)

    try:
        DSS.new(ECCPublicKey, "fips-186-3").verify(verificationSHA256Hash, digitalSignature)
        return "\nSignature is valid"
    except:
        return "\nSignature is invalid"
    
plaintext = input("Enter plaintext: ").encode()
ECCKey = ECC.generate(curve="P-256")
privateKey = ECCKey.export_key(format="PEM")
publicKey = ECCKey.public_key().export_key(format="PEM")
digitalSignature = generate_signature(privateKey, plaintext)

print("\nPrivate key: ", privateKey)
print("\nPublic key: ", publicKey)
print("\nDigital signature: ", digitalSignature)
print(verify_signature(publicKey, plaintext, digitalSignature))