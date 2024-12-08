# VT-Not-So-Pretty

Python data exfiltration tool that uses VirusTotal as it infrastructure.

As defenders we often overwhelmed by the sheer amount of network traffic in a network and overlook traffic made to well known trusted sites without any known suspicious functionalities (like file/software sharing sites). And what other site is more well known and trusted to defenders them virustotal.  

My main goal was to use virustotal upload and download functionalities to transfer files back and forth without the need to use our own infrastructure, and those braking the diamond model from the defenders perspective. 

The tool is pretty simple just provide it a path when promted (or using -f), your VT API key, and a hash of a file (already uploded to VT) to which you want the hashes of the files exfiltred to be write to, to be able to download then later on.    

![Vy-Not-So-Pretty](https://github.com/user-attachments/assets/780fec17-50da-4aef-a91e-d3682be5c573)

After uploading the files for exfiltration to VT all you have to do is to copy their hashes from the file community section (of the hash that you provided) search them and download them (require a VT premium API key).
![image](https://github.com/user-attachments/assets/5eb0067c-72bf-4628-bb7f-d9dfec508649)
![image](https://github.com/user-attachments/assets/89ff0f8f-73c1-49dd-bc49-eb98732a74d7)
