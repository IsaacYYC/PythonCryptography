import hashlib

rainbowTable = {}

commonPasswords = ["password", "admin", "letmein", "123456", "test"]

for password in commonPasswords:
    hashValue = hashlib.sha256(password.encode()).hexdigest()
    rainbowTable[hashValue] = password

passwordToCrack = input("enter passwrod to crack: ")
hashedPassword = hashlib.sha256(passwordToCrack.encode()).hexdigest()

if hashedPassword in rainbowTable:
    print("password ", {rainbowTable[hashedPassword]}, " found for hash", {hashedPassword})
else:
    print("not found")