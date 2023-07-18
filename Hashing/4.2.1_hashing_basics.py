import hashlib

def hash(plaintext):
    md5Hash = hashlib.md5(plaintext).hexdigest()
    sha1Hash = hashlib.sha1(plaintext).hexdigest()
    sha256Hash = hashlib.sha256(plaintext).hexdigest()

    print("MD5: ", md5Hash)
    print("sha1: ", sha1Hash)
    print("sha256: ", sha256Hash)

plaintext = input("Enter plaintext: ").encode("ASCII")

hash(plaintext)