import hashlib

def sha256_hash_password(examplePassword, inputPassword):

    exampleSHA256Hash = hashlib.sha256(examplePassword).hexdigest()
    inputSHA256Hash = hashlib.sha256(inputPassword).hexdigest()

    print("example password: ", examplePassword.decode("ASCII"))
    print("example SHA256 hash: ", exampleSHA256Hash)
    print("input password: ", inputPassword.decode("ASCII"))
    print("input SHA256 hash: ", inputSHA256Hash)

    if (exampleSHA256Hash == inputSHA256Hash):
        print("passwords match")
    else:
        print("passowrds do not match")

examplePassword = "password123".encode("ASCII")
inputPassword = input("please enter password: ").encode("ASCII")

sha256_hash_password(examplePassword, inputPassword)