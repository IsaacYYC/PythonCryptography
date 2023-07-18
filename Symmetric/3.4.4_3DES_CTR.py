from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

def DES3_CTR_encrypt(plaintext, DES3Key, nonce):

    DES3_CTR_cipher = DES3.new(DES3Key, DES3.MODE_CTR, nonce=nonce)
    ciphertext = DES3_CTR_cipher.encrypt(plaintext)
    return ciphertext

def DES3_CTR_decrypt(ciphertext, DES3Key, nonce):

    DES3_CTR_cipher = DES3.new(DES3Key, DES3.MODE_CTR, nonce=nonce)
    plaintext = DES3_CTR_cipher.decrypt(ciphertext)
    return plaintext

plaintext = input("Enter plaintext: ").encode()

DES3Key = DES3.adjust_key_parity(get_random_bytes(24))

nonce = get_random_bytes(7)

ciphertext = DES3_CTR_encrypt(plaintext, DES3Key, nonce)

decryptedPlaintext = DES3_CTR_decrypt(ciphertext, DES3Key, nonce)

print("plaintext: ", plaintext.decode())
print("cipehrtext: ", ciphertext.hex())
print("decrypted plaintext: ", decryptedPlaintext.decode())