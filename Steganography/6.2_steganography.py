from PIL import Image
import stepic

exampleImagePath = "example_image.png"
message = "This image contains this text"

exampleImage = Image.open(exampleImagePath).convert("RGBA")
messageBytes = message.encode()

steganography = stepic.encode(exampleImage, messageBytes)
steganographyImagePath = "stegonography_image.png"
steganography.save(steganographyImagePath)

steganographicImage = Image.open(steganographyImagePath)
decodedMessage = stepic.decode(steganographicImage)

print("Decoded message: ", decodedMessage)