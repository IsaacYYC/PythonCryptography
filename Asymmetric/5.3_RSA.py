from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def encrypt_symmetric_key(symmectricKey, publicKey):

    RSACipher = PKCS1_OAEP.new(RSA.import_key(publicKey))
    encryptedSymmetricKey = RSACipher.encrypt(symmectricKey)
    return encryptedSymmetricKey

def decrypt_symmetric_key(EncryptedSymmectricKey, publicKey):

    RSACipher = PKCS1_OAEP.new(RSA.import_key(publicKey))
    decryptedSymmetricKey = RSACipher.decrypt(EncryptedSymmectricKey)
    return decryptedSymmetricKey

def encrypt_plaintext(symmetricKey, nonce, plaintext):

    symmetricCipher = AES.new(symmetricKey, AES.MODE_GCM, nonce=nonce)
    ciphertext = symmetricCipher.encrypt(plaintext)
    return ciphertext


def decrypt_plaintext(symmetricKey, nonce, ciphertext):

    symmetricCipher = AES.new(symmetricKey, AES.MODE_GCM, nonce=nonce)
    decryptedPlaintext = symmetricCipher.decrypt(ciphertext)
    return decryptedPlaintext

symmetricKey = get_random_bytes(16)
nonce = get_random_bytes(12)

plaintext = input("enter your plaintext: ").encode()

RSAKey = RSA.generate(2048)

privateKey = RSAKey.export_key(format="PEM")
publicKey = RSAKey.publickey().export_key(format="PEM")

encryptedSymmetricKey = encrypt_symmetric_key(symmetricKey, publicKey)
decryptedSymmetricKey = decrypt_symmetric_key(encryptedSymmetricKey, privateKey)

ciphertext = encrypt_plaintext(symmetricKey, nonce, plaintext)
decryptedPlaintext = decrypt_plaintext(symmetricKey, nonce, ciphertext)

print("\nPrivate key: ", privateKey.decode())
print("\nPublic key: ", publicKey.decode())
print("\nSymmectric key: ", symmetricKey.hex())
print("\nEncrypted symmetric key: ", encryptedSymmetricKey.hex())
print("\nDecrypted symmetric key: ", decryptedSymmetricKey.hex())
print("\nPlaintext: ", plaintext.decode())
print("\nCiphertext: ", ciphertext.hex())
print("\nDecrypted plaintext: ", decryptedPlaintext.decode())