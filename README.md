# Nmap Packet Sniffer
This repository hosts a project that contains a custom packet sniffer with libpcap that can isolate Nmap OS detection packets.

# What is Nmap?
Nmap is an open source tool commonly used for network exploration, security auditing, reconnaisance, and more.
It was founded in 1997 by Gordon Lyon, and still receives continuous updates to this day. Learn more at Nmap's official [website](https://nmap.org). 

# Notes on Usage
 - This project currently runs on Unix-based operating systems to be able to use the libpcap package.
 - This version currently runs on the wlan0 interface by default.
 - This project implements Zenity to display windows. Zenity is an open-source platform that simplifies GUI creation by providing easy methods for developers to create GUI elements in their programs.

# How Does It Work?
This Nmap Packet Sniffer uses IBM's libpcap package to provide the foundation for packets to be captured. This foundation is implemented as follows:
 1. Look up the network device to capture packets on (wlan0 by default) and confirm it exists. This uses `pcap_lookupnet()`.
 2. Open the network device for packet capture using `pcap_open_live()`.
 3. Filters network traffic for TCP traffic (a main protocol used in OS detection) using `pcap_compile()` and `pcap_setfilter()`.
 4. Processes each packet captured in a loop using `pcap_loop()`.

## Then How are Packets Processed?
One of the parameters for `pcap_loop()` is a callback function that is called everytime a packet is captured and needs to be processed.
This callback function is meant to be user-defined. As a project that aims to dissect Nmap packets, the callback function does the following for each captured packet:
 1. Unpack the packet from the data link and network layers using arpa/inet.h and various netinet header structures.
 2. Access the TCP header and assign it to a pre-defined netinet structure.
 3. Check various TCP header fields for known fingerprints of Nmap packets. For this version that currently detects OS scans:
	- Inspect TCP window sizes for unusually small numbers (1, 4, 16, 63, 128, 256, 512, 1024).
	- Attempt to match window sizes to combinations of set flag bits in the packet.
 4. Print additional packet statistics, such as packet size, host IP, and payload.

# Pros
 - Lightweight program that processes packets incredibly fast.
 - Well-documented source code allows for readability.
 - Is scalable for implementation of future Nmap scan detectors as well as flags and other runtime options.
 - Can be added as a daemon to run in the background. 

# Cons
 - Encountered some issues trying to run on wlan0 (wifi) interface while eth0 (ethernet) interface was up and running. This is why the current version runs on wlan0 by default. 
 - Limited flag options in current version.

# How to Use
 - Install the libpcap library using your machine's package manager.
 - Install the Zenity library using your machine's package manager. 
 - Clone this repository to your local machine.
 - Compile the 'packet_sniffer.c' file with the libpcap library.
 ```
 gcc packet_sniffer.c -o <filename> -lpcap
 ```
 - Run the resulting executable.

# Current Supported Flags
 - `-v`: enables verbosity. If not enabled, program will only report Nmap scans. If enabled, program will print additional packet statistics. 



