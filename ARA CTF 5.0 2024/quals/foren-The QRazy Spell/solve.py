import cv2
from pyzbar.pyzbar import decode
import imageio

# Function to read QR codes from a list of image frames
def read_qr_codes_from_frames(frames):
    for frame in frames:
        # Decode QR codes using pyzbar
        decoded_objects = decode(frame)

        # Loop through the detected QR codes
        for obj in decoded_objects:
            data = obj.data.decode('utf-8')
            print(f"{data}", end="")

if __name__ == "__main__":
    for i in range(307):  # Iterate from 000 to 306
        # Generate the file name dynamically
        gif_path = f"/home/mirai/ctf/ARA CTF 5.0 2024/quals/foren-The QRazy Spell/ezgif-2-9152ce55f3-gif-im/frame_{i:03d}_delay-0.2s.gif"

        try:
            # Read all frames from the GIF using imageio
            frames = imageio.mimread(gif_path)

            # print(f"Reading QR codes from {gif_path}")
            read_qr_codes_from_frames(frames)
        except FileNotFoundError:
            print(f"File not found: {gif_path}")
