
#!/usr/bin/python

#################################################################################
# Tool Name       : PacketManipulator.py
#
# Author          : Tarig Mudawi 
#                   Dakota State University
#
# Tool Description: This tool uses the scapy python module to capture packets, create
#                   custom packets and reroute and modify packets.
#                   This tool could be used to capture and inspect packets or to create
#                   and manipulate packets on the fly to accomplish specific tasks.
#
################################################################################## 


import sys
from StringIO import StringIO
from scapy.layers import inet
from scapy.all import *
from scapy.utils import PcapWriter


## Create a Packet Counter
counter = 0


## Define our Custom Action function
def custom_action(packet):
    global counter
    counter += 1

    #myIP = str(input("Enter IP address to reroute the packet: "))

    while(True):
        # First enter source and destination IPs
        try:
            myIP = str(input("Enter IP address to reroute the packet: "))
            if(validIP(myIP)):
                break
            else:
                continue
        except ValueError:
            pass


    # Manipulate source ip here
    packet[0][1].src = myIP

    # We write something in the packet that profes that we modified it
    payload = raw_input("Enter a string or anything to show in the packet payload: ")

    # Now inject your fake source IP and resend the packet, 
    # I named as spoofed packet


    spoofed_packet = IP(src=myIP, dst=packet[0][1].dst)/TCP()/payload

    spoofed_packet.show()

    # Now we simply send the packet to original destination
    send(spoofed_packet)

    # Check the packet contents
    return 'Packet #{}: Source IP: {} ==> Destination IP: {}'.format(counter, packet[0][1].src, packet[0][1].dst)


def saveToPcapFile(pcap_file, pkt):

    pktdump = PcapWriter(pcap_file, append=True, sync=True)

    pktdump.write(pkt)


def pkt_callback(pkt):

    pkt.show() # debug statement

    saveToPcapFile(pcap_file, pkt)


def sniff_packet(pcap_file):
    
    # sniff live packet and display information or capture in pcap file
    packets = sniff(prn=pkt_callback, filter="ip", store=0, count=0)


def create_packet():
    '''This function allow you to create and send your custom packet'''

    while(True):
        # First enter source and destination IPs
        try:
            dst_ip = str(input("Enter a destination IP: "))
            if(validIP(dst_ip)):
                break
            else:
                continue
        except ValueError:
            pass

    while(True):
        try:
            src_ip = str(input("Enter a source IP: "))
            if(validIP(src_ip)):
                break
            else:
                continue
        except ValueError:
            pass

    while(True):
        try:
            src_port = int(input("Enter a source port: "))
            if(validPort(src_port)):
                break
            else:
                continue
        except ValueError:
            pass

    while(True):
        try:
            dst_port = int(input("Enter a destination port: "))
            if(validPort(dst_port)):
                break
            else:
                continue
        except ValueError:
            pass

    while(True):
        try:
            seq_num = int(input("Enter a sequence number: "))
            if(isvalidInt(seq_num)):
                break
            else:
                continue
        except ValueError:
            pass


    payload = input("Enter a string to show in the packet's payload: ")

    packet = IP(dst=dst_ip, src=src_ip)/TCP(sport=src_port, dport=dst_port, seq=seq_num)/payload

    packet.show()

    send(packet)


def validIP(address):
    '''Validate IP Address'''

    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True


def validPort(port):
    if(0 <= port <= 65535):
        return True
    else:
        return False


def isvalidInt(num):
    if(type(num) == int):
        return True
    else:
        return False


def Packet_Options():
    ans=True
    while ans:
        print("""
        1. Sniff Packets.
        2. Create Packets.
        3. Modify & Reroute a Packet.      
        4.Exit/Quit
        """)
    
        ans=raw_input("Please select an option\n")
       
        if ans=="1":
            global pcap_file
            pcap_file = raw_input("Enter a pcap file path to save the packets: ")

            dir_name = os.path.dirname(pcap_file)

            print(dir_name)

            # Check if directory and file ext. are good 
            while 1:
                 if not(os.path.exists(dir_name)):
                     pcap_file = raw_input("Please enter a valid path to the file: ")
                     dir_name = os.path.dirname(pcap_file)
                     continue
                 elif not(pcap_file.endswith('.pcap')):
                     pcap_file = raw_input("Enter a file with .pcap_file extension: ")
                     continue
                 else:
                    break

            print("\nSniffing Packets...")
            sniff_packet(pcap_file)
            break
        elif ans=="2":
            print("\n Packet Created...")
            create_packet()
        elif ans=="3":
            print("\n Packet Modified and Rerouted...")
            ## Setup sniff, filtering for IP traffic
            sniff(filter="ip", prn=custom_action)
            break
        elif ans=="4":
            print("\n Exiting...") 
            ans = None
        else:
            print("\n Not Valid Choice Please Try again")


def main():
    
    Packet_Options()


if __name__ =="__main__":
    main()