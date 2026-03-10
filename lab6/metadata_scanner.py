import os
import time
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS
from pathlib import Path
import base64
import re

def detect_base64(value):
    # Check if value is a string and looks like Base64 (A-Z, a-z, 0-9, +, /)
    # Must be at least 8 chars long and have no spaces
    if isinstance(value, str) and len(value) > 8 and " " not in value:
        if re.match(r"^[A-Za-z0-9+/]+={0,2}$", value):
            try:
                # Try to decode it
                decoded = base64.b64decode(value).decode('utf-8')
                # check to see if there is something readable
                if all(32 <= ord(c) <= 126 for c in decoded):
                    return decoded
            except:
                pass
    return None

def analyze_image(file_path):
    print(f"\n========== Analyzing {file_path}=========")
    img = Image.open(file_path)

    image_risk_score = 0
    exif_data = img._getexif()

    exif_dict = {}
    if exif_data:
        for (tag_key, tag_value) in exif_data.items():
            tag_name = TAGS.get(tag_key, tag_key)
            print(f"{tag_name}: {tag_value}")
            exif_dict[tag_name] = tag_value

            decoded_base64 = detect_base64(tag_value)
            if decoded_base64:
                print(f"Base 64 value deteceted and decoded: {decoded_base64}")
                tag_value = decoded_base64
            
            if tag_name == 'UserComment' and isinstance(tag_value, bytes):
                # UserComments often start with 8 bytes of encoding info (e.g., 'ASCII\x00\x00\x00')
                try:
                    clean_value = tag_value[8:].decode('utf-8', errors='ignore').strip()
                except:
                    clean_value = str(tag_value)
            else:
                clean_value = str(tag_value).strip()

            command_regex = r"^[A-Z]{4,8}:\s"

            if re.search(command_regex, clean_value):
                print(f"----RISK: Covert Channel found: {clean_value} (10 Points)")
                image_risk_score += 10

        # GPS / Privacy Leak
        if "GPSInfo" in exif_dict:
            print("----RISK: GPS info present in image (5 points)")
            image_risk_score += 5
        
        # Timestamp Anomaly
        file = Path(file_path)
        file_stat = file.stat()
        time_anomaly = False

        access_time = datetime.fromtimestamp(file_stat.st_atime)
        modify_time = datetime.fromtimestamp(file_stat.st_mtime)
        birth_time = datetime.fromtimestamp(file_stat.st_ctime)
        
        if 'DateTimeOriginal' in exif_dict:
            print('has time')
            exif_time = datetime.strptime(exif_dict['DateTimeOriginal'], '%Y:%m:%d %H:%M:%S')
            print(exif_time)
            print(birth_time)
            if exif_time != birth_time:
                print(f"----RISK: EXIF Time ({exif_time}) does not match the system MAC time.")
                time_anomaly = True

            if exif_time > modify_time:
                print(f"----RISK: Modify time ({modify_time} is before EXIF time ({exif_time}))")
                time_anomaly = True

        # OS MAC time comparison
        if birth_time > modify_time:
            print(f"----RISK: birth time ({birth_time}) is after modify time ({modify_time})")
            time_anomaly = True
        
        if modify_time > access_time:
            print(f"----RISK: modify time ({modify_time}) is after access time ({access_time})")
            time_anomaly = True

        if time_anomaly:
            print("Timestamp risk exists, adding 5 points")
            image_risk_score += 5

        # Editing/Compression detection
        if 'Software' in exif_dict:
            print(f"----RISK: Editing software detected in EXIF metadata: {exif_dict['Software']}")
            image_risk_score += 5
    else:
        print(f"----RISK: Missing EXIF metadata in image (10 points)")
        image_risk_score += 10

    if img.info:
        for info_key, info_value in img.info.items():
            print(f"{info_key}: {info_value}")
            if isinstance(info_value, bytes):
                val_str = info_value.decode('utf-8', errors='ignore').strip()
            else:
                val_str = str(info_value).strip()
            decoded = detect_base64(val_str)
            
            check_val = decoded if decoded else val_str
            if re.search(r"^[A-Z]{4,8}:\s", check_val):
                print(f"----RISK: Covert Channel found in PNG Info ({info_key}): {check_val}")
                image_risk_score += 10

    print("-------------------------------------")
    print(f"TOTAL RISK SCORE: {image_risk_score}")


def main():
    folder_path = Path("/home/user/fsct8561/security_applications/lab6/Images/")
    if not folder_path.exists():
        print(f"Error: Path {folder_path} not found.")
        return

    for img_file in folder_path.glob("*.png"):
        analyze_image(img_file)

if __name__ == "__main__":
    main()