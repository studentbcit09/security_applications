from PIL import Image
import stepic

# Load carrier image
carrier = Image.open('lab8/profile_secret.png')

# Encode and save
stego_msg = stepic.decode(carrier)
print(stego_msg)