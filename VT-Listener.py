import requests
import time
import argparse
import pyfiglet
import os

result = pyfiglet.figlet_format("VT Not so pretty listener by YanivG")
print(result)

# Argument Parser for folder, API key, and file hash input
parser = argparse.ArgumentParser(description="VT not so pretty by YanivG")
parser.add_argument('-f', '--folder', type=str, help="Path to the folder you want to save files to")
parser.add_argument('-k', '--api_key', type=str, help="Your Premium VirusTotal API key")
parser.add_argument('-c', '--comments_file_hash', type=str, help="Hash to check comment on in VirusTotal")
parser.add_argument('-d', '--delete_api_key', type=str, help="API key for deleting comments after download - this should be the one used for file upload", required=False)

args = parser.parse_args()

# Function to validate if a folder path exists
def validate_folder_path(folder_path):
    return os.path.isdir(folder_path)

# Prompt the user if folder from arguments isn't provided
folder_path = args.folder if args.folder else input("Please enter the folder path you want to save files to: ")

# Validate folder path
while not validate_folder_path(folder_path):
    print("Invalid folder path. Please enter a valid folder path.")
    folder_path = input("Please enter the folder path you want to save files to: ")

# Prompt the user if API key from arguments isn't provided
api_key = args.api_key if args.api_key else input("Please enter your Premium VirusTotal API key: ")

# Prompt the user if Hash from user arguments isn't provided
file_hash = args.comments_file_hash if args.comments_file_hash else input("Please enter the file hash to check comments on in VirusTotal: ")

# Get delete API key from arguments
delete_api_key = args.delete_api_key if args.delete_api_key else None

url = f'https://www.virustotal.com/api/v3/files/{file_hash}/comments'

# Headers for main API requests
headers = {
    'x-apikey': api_key  
}

# Headers for DELETE requests
delete_headers = {
    'x-apikey': delete_api_key
} if delete_api_key else None

# Function to download file based on hash from comments
def download_file(file_hash):
    try:
        # URL for file download
        download_url = f'https://www.virustotal.com/api/v3/files/{file_hash}/download'
        
        # Request to download file
        response = requests.get(download_url, headers=headers, stream=True)
        
        # Check if request was successful
        if response.status_code == 200:
            file_name = os.path.join(folder_path, f"{file_hash}.vt")  # Save file using the hash as the file name and the extension .vt
            with open(file_name, 'wb') as file:
                for chunk in response.iter_content(1024):
                    if chunk:
                        file.write(chunk)
            print(f"File {file_hash} downloaded successfully.")
        else:
            print(f"Failed to download file {file_hash}: {response.status_code}")
    except Exception as e:
        print(f"Error downloading file {file_hash}: {e}")

# Function to delete a comment based on ID
def delete_comment(comment_id):
    if delete_headers:
        try:
            # URL for deleting the comment
            delete_url = f"https://www.virustotal.com/api/v3/comments/{comment_id}"
            
            # Request to delete the comment
            response = requests.delete(delete_url, headers=delete_headers)
            
            if response.status_code == 200:
                print(f"Comment with ID {comment_id} deleted successfully.")
            else:
                print(f"Failed to delete comment with ID {comment_id}: {response.status_code}")
        except Exception as e:
            print(f"Error deleting comment {comment_id}: {e}")
    else:
        print("No API key provided for comment deletion. Skipping comment deletion.")

# Function to get and print the comments, and then download files based on hashes
def get_comments():
    try:
        # Make the request to VirusTotal API to get comments on the file
        response = requests.get(url, headers=headers)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            
            # Extract comments from the 'data' array in the response
            comments = data.get('data', [])
            
            if comments:
                print("Comments:")
                for comment in comments:
                    # Extract and print the comment text
                    comment_text = comment["attributes"].get('text', 'No comment available')
                    print(f"Comment: {comment_text}")
                    
                    # Check if the comment contains a file hash
                    # Assuming the hashes are alphanumeric strings of length 64
                    possible_hash = comment_text.strip()
                    if len(possible_hash) == 64:  # Check if it's a valid SHA256 hash length
                        print(f"Found hash in comment: {possible_hash}")
                        download_file(possible_hash)
                        
                        # Delete the comment after processing it (if delete_api_key is provided)
                        if delete_headers:
                            comment_id = comment["id"]
                            delete_comment(comment_id)
            else:
                print("No comments available.")
        else:
            print(f"Failed to retrieve data: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# Loop to call the function every 2 minutes
while True:
    get_comments()
    # Waiting for 2 minutes (120 seconds) before the next request
    
    print("Waiting for new comments for 2 minutes")
    time.sleep(120)
