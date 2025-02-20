# NMAP Packet Sniffer
This repository hosts a project that contains a custom packet sniffer with libpcap that can isolate NMAP OS detection packets.

# Notes on Usage
This project currently runs on Unix-based operating systems to be able to use the libpcap package. 

# How to Use
 - Install the libpcap library using your machine's package manager.
 - Install the Zenity library using your machine's package manager. 
 - Clone this repository to your local machine.
 - Compile the 'packet_sniffer.c' file with the libpcap library.
 ```
 gcc packet_sniffer.c -o <filename> -lpcap
 ```
 - Run the resulting executable.



