ciphertext = "foxs, fsns, fsms. od de, lbedo?"

def caesar_bruteforce(ciphertext):

    for shiftKey in range(0, 25):
        decrypetedPlaintext = ""

        for char in ciphertext:

            if char.islower():
                charIndex = ord(char) - ord("a")
                charUnshifted = (charIndex - shiftKey) % 26 + ord("a")
                charDecrypted = chr(charUnshifted)
                decrypetedPlaintext += charDecrypted
            else:
                decrypetedPlaintext += char
        print ("With a shift of: " +str(shiftKey) + " the decrypted text is: " + decrypetedPlaintext)
caesar_bruteforce(ciphertext)

                