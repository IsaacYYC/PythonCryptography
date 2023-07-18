def encrypt(plaintext, shiftKey):
    ciphertext = ""
    
    for char in plaintext:
        
        if char.isupper():
            charIndex = ord(char) - ord("A")
            charShifted = (charIndex + shiftKey) % 26 + ord("A")
            charEncrypted = chr(charShifted)
            ciphertext += charEncrypted
        
        elif char.islower():
            charIndex = ord(char) - ord("a")
            charShifted = (charIndex + shiftKey) % 26 + ord("a")
            charEncrypted = chr(charShifted)
            ciphertext += charEncrypted
        
        else:
            ciphertext += char
    
    return ciphertext

def decrypt(cipherText, ShiftKey):
    decryptedPlaintext = ""

    for char in cipherText:
        
        if char.isupper():
            charIndex = ord(char) - ord("A")
            charUnshifted = (charIndex - ShiftKey) % 26 + ord("A")
            charDecrypted = chr(charUnshifted)
            decryptedPlaintext += charDecrypted
        
        elif char.islower():
            charIndex = ord(char) - ord("a")
            charUnshifted = (charIndex - ShiftKey) % 26 + ord("a")
            charDecrypted = chr(charUnshifted)
            decryptedPlaintext += charDecrypted

        else:
            decryptedPlaintext += char

    return decryptedPlaintext

plainText = input("Enter plain text: ")
#shiftKey = input("Enter shift key: ")
shiftKey = 10
cipherText = encrypt(plainText, shiftKey)
decryptedPlaintext = decrypt(cipherText, shiftKey)

print("PlainText: " + plainText)
print("Character shift: " + str(shiftKey))
print("Encrypted plainText: " + cipherText)
print("decrypted plainText: " + decryptedPlaintext)