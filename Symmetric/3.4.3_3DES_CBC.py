from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

def DES3_CBC_encrypt(plaintext, DES3Key, initializationVector):

    DES3_CBC_cipher = DES3.new(DES3Key, DES3.MODE_CBC, iv=initializationVector)
    ciphertext = DES3_CBC_cipher.encrypt(pad(plaintext, DES3.block_size))
    return ciphertext

def DES3_CBC_decrypt(ciphertext, DES3Key, initializationVector):

    DES3_CBC_cipher = DES3.new(DES3Key, DES3.MODE_CBC, iv=initializationVector)
    plaintext = unpad(DES3_CBC_cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext

plaintext = input("Enter plaintext: ").encode()

DES3Key = DES3.adjust_key_parity(get_random_bytes(24))

initializationVector = get_random_bytes(8)

ciphertext = DES3_CBC_encrypt(plaintext, DES3Key, initializationVector)

decryptedPlaintext = DES3_CBC_decrypt(ciphertext, DES3Key, initializationVector)

print("plaintext: ", plaintext.decode())
print("cipehrtext: ", ciphertext.hex())
print("decrypted plaintext: ", decryptedPlaintext.decode())