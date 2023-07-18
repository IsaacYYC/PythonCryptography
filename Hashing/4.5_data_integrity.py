import hashlib

def calculate_checksum(filePath):
    
    with open(filePath, "rb") as f:

        fileHash = hashlib.sha256()
        while chunk := f.read(4096):
            fileHash.update(chunk)
    return fileHash.hexdigest()

filePath = "example_file.txt"

checksum = calculate_checksum(filePath)

print("the checksum of ", filePath, " is ", checksum)

with open(filePath, "w") as f:

    f.write("This file has been modified")

newChecksum = calculate_checksum(filePath)
print("the new checksum is ", newChecksum)

if checksum == newChecksum:
    print("This file has not been tampered with")
else:
    print("this file has been tampered with")