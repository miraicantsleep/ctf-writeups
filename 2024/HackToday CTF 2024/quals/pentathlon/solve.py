from PIL import Image

image = Image.open("chall4.png")
pixels = image.load()

extracted_msg = []
i = 0
while True:
    try:
        r, g, b = pixels[i*3, 0]
        original_g = g ^ b 
        extracted_char = r ^ original_g
        extracted_msg.append(chr(extracted_char))
        i += 1
    except IndexError:
        break

secret_message = ''.join(extracted_msg)

print(secret_message)