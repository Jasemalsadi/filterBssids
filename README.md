# Filter BSSIDs
Filter unique BBSIDs that leak TCP or UDP traffic. 
## Prerequisites
```
Python 3
OptionParser
scapy
```
## Install

```bash
$ pip3 install -r requirements.txt
```
## Attributes 
```
-s : Path to the PCAP file. 
-p : Destination path to save the filtered BSSIDs in txt file.
```


## Example 
```bash
$ python3 filter_unique_mac.py -s "/Users/Jasem/Desktop/traffic.pcap" -d "/Users/Jasem/Desktop/"
```
