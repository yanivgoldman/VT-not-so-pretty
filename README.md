# VT-Not-So-Pretty

Python data exfiltration tool that uses VirusTotal as it infrastructure.

My main goal was to use virustotal upload and download functionalities to transfer files back and forth without the need to use our own infrastructure, and those braking the diamond model from the defenders perspective. 

The tool is pretty simple just prodive it a path when promted (or using -f), your VT API key, and a hash of a file (already uploded to VT) to which you want the hashes of the files exfiltred to be write to, to be able to download then later on.    

![Vy-Not-So-Pretty](https://github.com/user-attachments/assets/780fec17-50da-4aef-a91e-d3682be5c573)
