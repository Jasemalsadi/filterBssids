import sys
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import TCP, UDP
import datetime
from optparse import OptionParser


def main():
    if (sys.version_info < (3, 0)):
        print("U need to run the code in python 3 ")
        sys.exit()
    # parse command line
    parser = OptionParser(usage="usage: %prog [options], version=%prog 1.0")

    parser.add_option("-s", "--source", action="store", type="string", dest="source_pcap_path", default=False,
                      help="Path to the PCAP file  ")

    parser.add_option("-d", "--destination", action="store", type="string", dest="destination_filtered_path",
                      default=False,
                      help="Destination path to save the filtered BSSIDs")

    (options, args) = parser.parse_args()
    if len(vars(options)) != 2 or not options.source_pcap_path or not options.destination_filtered_path:
        parser.print_help()
        sys.exit()
    sourcPcap = options.source_pcap_path.replace("\\", "").strip()
    saveDir = options.destination_filtered_path.strip()
    print(" Reading the PCAP file ... \n")
    packets = rdpcap(sourcPcap)
    BSSIDs = []
    count = 0
    print(" Filtering TCP and UDP packets  ... \n")
    for packet in packets:
        if (packet.haslayer(UDP) or packet.haslayer(TCP)) and packet.haslayer(Dot11):  # if it's UDP of TCP packet
            BSSIDs.append(packet.addr3)
            count += 1
    print("Done filtering, number of filtered packets " + str(count) + "\n")
    print("Removing Duplicate BSSIDs and writing it to file ...\n")
    unique_BSSIDs = list(set(BSSIDs))
    ts = int(datetime.datetime.now().timestamp())
    with open(os.path.join(saveDir, "BSSIDs" + "-" + str(ts) + ".txt"), "w") as f:  # Opens file and casts as f
        for bssid in unique_BSSIDs:
            f.write(bssid + "\n")  # Writing

    print("Done ...\n")
main()
