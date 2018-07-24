Tool Description:
===

This tool  can be used to capture and investigate network packets, the tool also allow users to create and modify packets.


Technical Specification:
===

* Windows 10 Operating System.
* Python 2.7
* No other dependencies or third-party library needed.


Usage:
===

As illustrated below, the user simply needs to specify the word python followed by the script name.

C:\Python27>python C:\CSC842\PacketManipulator.py

1- Option 1 allow users to capture packets into a pcap file which can be reviewed and investigated later.
2- Optoin 2 allow users to create custom packets. The user is prompted to enter source and destination 
     IPs and ports, a sequence number and a text to enter in the packet's payload.
3- Option 3 allow users to capture, modify and reroute a packet. The user can change the source IP of the
     packet and also enter some text into the packet payload proving that he/she modified the packet.
4- Option 4 is simply to exit the script.

 

 

