from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

def AES_CBC_encrypt(plaintext, AESKey, initializationVector):

    AES_CBC_cipher = AES.new(AESKey, AES.MODE_CBC, iv=initializationVector)
    ciphertext = AES_CBC_cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def AES_CBC_decrypt(ciphertext, AESKey, initilizationVector):

    AES_CBC_cipher = AES.new(AESKey, AES.MODE_CBC, iv=initilizationVector)
    decryptedPlaintext = unpad(AES_CBC_cipher.decrypt(ciphertext), AES.block_size)
    return decryptedPlaintext

plaintext = input("Enter plaintext: ").encode("ASCII")

AESKey = get_random_bytes(16)

initializationVector = get_random_bytes(16)

ciphertext = AES_CBC_encrypt(plaintext, AESKey, initializationVector)

decryptedPlaintext = AES_CBC_decrypt(ciphertext, AESKey, initializationVector)

print("plaintext: ", plaintext.decode("ASCII"))
print("cipehrtext: ", ciphertext.hex())
print("decrypted plaintext: ", decryptedPlaintext.decode("ASCII"))
