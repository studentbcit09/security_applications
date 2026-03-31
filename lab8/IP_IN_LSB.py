import steganography_LSB as sl
from PIL import Image

# 2. Manipulate the steganography_LSB.py file to hide 'TARGET:192.168.1.50' inside
# company_logo.png using manual LSB manipulation
# 1. Open company_logo.png and convert to RGBA mode.
# 2. Use getdata() to access pixel array.
# 3. Use the provided set_LSB() function to hide the string "TARGET:192.168.1.50" in
# the first 10 pixels.
# 4. Save the modified image as company_logo_stego.png.
# 5. Save the file as IP_IN_LSB.py.
# 6. Run the file. 

def inject_message():
    original_image = Image.open('lab8/company_logo.png')
    rgba_image = original_image.convert('RGBA')
    output_img = Image.new(rgba_image.mode, rgba_image.size)

    pixList = list(rgba_image.getdata())
    newArray = []

    message = 'TARGET:192.168.1.50'

    # copied from steganography_LSB.py
    for i in range(len(message)):
        charInt = ord(message[i])
        cb = str(bin(charInt))[2:].zfill(8)
        pix1 = pixList[i*2]
        pix2 = pixList[(i*2)+1]
        newpix1 = []
        newpix2 = []

        for j in range(0,4):
            newpix1.append(sl.set_LSB(pix1[j], cb[j]))
            newpix2.append(sl.set_LSB(pix2[j], cb[j+4]))

        newArray.append(tuple(newpix1))
        newArray.append(tuple(newpix2))

    newArray.extend(pixList[len(message)*2:])

    output_img.putdata(newArray)
    output_img.save('lab8/company_logo_stegno.png')

if __name__ == "__main__":
    inject_message()
