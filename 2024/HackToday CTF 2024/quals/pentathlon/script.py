from PIL import Image

message = open("secret.txt", "r").read()
msg = [ord(m) for m in message]

image = Image.open("chall4_original.png")
pixels = image.load()

for i in range(len(msg)):
    r, g, b = pixels[i*3,0]
    pixels[i*3,0] = msg[i]^g, g^b, b

image.save("chall4.png")