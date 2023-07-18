from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def generate_mac(SymmectricKey, nonce, plaintext):

    symmetricCipher = AES.new(SymmectricKey, AES.MODE_GCM, nonce=nonce)
    mac = symmetricCipher.encrypt(plaintext)
    return mac

def generate_hmac(SymmectricKey, nonce, plaintext):

    hmacObject = HMAC.new(SymmectricKey, plaintext, digestmod=SHA256)
    hmacDigest = hmacObject.digest()
    symmetricCipher = AES.new(SymmectricKey, AES.MODE_GCM, nonce=nonce)
    ciphertext = symmetricCipher.encrypt(plaintext)
    ciphertextWithDigest = ciphertext + hmacDigest
    return ciphertextWithDigest

def generate_signature(privateKey, plaintext):

    RSAPrivateKey = RSA.import_key(privateKey)
    sha256Hash = SHA256.new(plaintext)
    digitalSignature = pkcs1_15.new(RSAPrivateKey).sign(sha256Hash)
    return digitalSignature

def verify_signature(publicKey, plaintext, digitalSignature):

    RSAPublicKey = RSA.import_key(publicKey)
    verificaitonSHA256Hash = SHA256.new(plaintext)

    try:
        pkcs1_15.new(RSAPublicKey).verify(verificaitonSHA256Hash, digitalSignature)
        return "\nSignature is valid"
    except:
        return"\nSignature is invalid"
    
symmetricKey = get_random_bytes(16)
nonce = get_random_bytes(12)

plaintext = input("enter your plaintext: ").encode()
mac = generate_mac(symmetricKey, nonce, plaintext)
ciphertextWithDigest = generate_hmac(symmetricKey, nonce, plaintext)

RSAKey = RSA.generate(2048)
privateKey = RSAKey.export_key()
publicKey = RSAKey.publickey().export_key()
digitalSignature = generate_signature(privateKey, plaintext)

print("\nMessage authenticaiton code: ", mac.hex())
print("\nHash-based message authentication code: ", ciphertextWithDigest.hex())
print("\nDigital signature: ", digitalSignature.hex())
print(verify_signature(publicKey, plaintext, digitalSignature))