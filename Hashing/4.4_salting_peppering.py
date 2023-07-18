import hashlib
from Crypto.Random import get_random_bytes

def hash_password(password, salt, pepper):
    
    SPPassword = salt + password.encode() + pepper
    hashedPassword = hashlib.sha256(SPPassword).hexdigest()
    return hashedPassword

password = input("ender password: ")
salt = get_random_bytes(16)
pepper = get_random_bytes(16)
hashedPassword = hash_password(password, salt, pepper)

print("hashed password", hashedPassword)