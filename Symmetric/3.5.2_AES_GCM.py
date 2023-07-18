from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AES_GCM_encrypt(plaintext, AESKey, nonce):

    AES_GCM_cipher = AES.new(AESKey, AES.MODE_GCM, nonce=nonce)
    ciphertext = AES_GCM_cipher.encrypt(plaintext)
    return ciphertext

def AES_GCM_decrypt(ciphertext, AESKey, nonce):

    AES_GCM_cipher = AES.new(AESKey, AES.MODE_GCM, nonce=nonce)
    plaintext = AES_GCM_cipher.encrypt(ciphertext)
    return plaintext

plaintext = input("Enter plaintext: ").encode("ASCII")

AESKey = get_random_bytes(16)

nonce = get_random_bytes(12)

ciphertext = AES_GCM_encrypt(plaintext, AESKey, nonce)

decryptedPlaintext = AES_GCM_decrypt(ciphertext, AESKey, nonce)

print("plaintext: ", plaintext.decode("ASCII"))
print("cipehrtext: ", ciphertext.hex())
print("decrypted plaintext: ", decryptedPlaintext.decode("ASCII"))


