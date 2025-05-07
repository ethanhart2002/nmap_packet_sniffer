#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <string.h>

// #define VERBOSITY argc > 2 ? ((strcomp(argv[2], "-v")))



// Documented window sizes for NMAP OS Scan TCP packets
uint16_t window_field_sizes[] = {1, 4, 16, 63, 128, 256, 512, 1024};
const char* SYSTEM_DISPLAY;

void show_warning_window(char* sourceIP);

typedef struct {
	int verbosity;
} Loop_args;

void callback_function (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	SYSTEM_DISPLAY = getenv("DISPLAY");
	Loop_args *l = (Loop_args *) args;
	int verbose = l->verbosity;
	//printf("Mode in callback (0 = Quiet, 1 = Verbose): %d \n", verbose);


	if (verbose == 1) printf("-----------------------------------------\n");

	struct ether_header *eth_header;
	struct ip *ip_header;
	struct tcphdr *tcp_header;

	// Make sure packet is a valid IP Packet by inspecting the ethernet header
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header->ether_type)!=ETHERTYPE_IP) {
		if (verbose == 1) printf("Not a valid IP packet.\n\n");
		return;
	}


	// Unpack the ip header from the ethernet layer (netinet/ip.h)
	ip_header = (struct ip *)(packet + sizeof(struct ether_header));

	// inet_ntoa() converts network address to string

	if (verbose == 1) printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));

	if (ip_header->ip_p == IPPROTO_TCP) {
		if (verbose == 1) printf("This is a TCP Packet. \n");



		// Strategy: Look for unusual window field sizes

		// Unpack the tcp header from the offsets of the ethernet header and ip header.
		// Ethernet header is fixed value most of the time, but the length of the ip header is variable. 
		tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

		// Network to host endian-ness (I think that's a word?) conversion
		uint16_t win_field = ntohs(tcp_header->th_win);
		if (verbose == 1) printf("TCP packet window length: %"PRIu16"\n", win_field);
		for (int i = 0; i < sizeof(window_field_sizes)/sizeof(uint16_t); i++) {
			if (window_field_sizes[i] == win_field) {
				if (verbose == 1) printf("Possible NMAP OS scan detected: Unusually small TCP Window Size Length of %" PRIu16 "\n", win_field);
			} 
		}

		// Print flags using bitwise operations with the flag definitions in netinet/tcp.h
		u_char tcp_flags = tcp_header->th_flags;
		if (verbose == 1) printf("TCP Flags in packet: ");
		if (verbose == 1) {
			if (tcp_flags & TH_SYN) printf("SYN ");
			if (tcp_flags & TH_RST) printf("RST ");
			if (tcp_flags & TH_PUSH) printf("PUSH ");
			if (tcp_flags & TH_FIN) printf("FIN ");
			if (tcp_flags & TH_ACK) printf("ACK ");
			if (tcp_flags & TH_URG) printf("URG ");
			printf("\n");
	  }



		// Strategy: Look at TCP flags in packet. NMAP OS Scans always have the packets with these following conditions. Flags are stored in bitmasks, which can be found in the header file netinet/tcp.h
		if (win_field == 128) {
			if (tcp_flags & 0) {
				if (verbose == 1) printf("Extremely probable NMAP OS scan detected: Unusually small TCP Window Size Length of %" PRIu16 " and TCP flag bits of 0x%03X match OS scan fingerprint.\n", win_field, 0x000);
				if (SYSTEM_DISPLAY != NULL) {
					show_warning_window(inet_ntoa(ip_header->ip_src));
				}
			}
		} else if (win_field == 256) {
			if (tcp_flags & 0x02b) {
				if (verbose == 1) printf("Extremely probable NMAP OS scan detected: Unusually small TCP Window Size Length of %" PRIu16 " and TCP flag bits of 0x%03X match OS scan fingerprint.\n", win_field, 0x02b);
				if (SYSTEM_DISPLAY != NULL) {
					show_warning_window(inet_ntoa(ip_header->ip_src));
				}
			}
		} else if (win_field == 1024) {
			if (tcp_flags & 0x010) {
				if (verbose == 1) printf("Extremely probable NMAP OS scan detected: Unusually small TCP Window Size Length of %" PRIu16 " and TCP flag bits of 0x%03X match OS scan fingerprint.\n", win_field, 0x010);
				if (SYSTEM_DISPLAY != NULL) {
					show_warning_window(inet_ntoa(ip_header->ip_src));
				}
			}
		}
	}

	//Print the packet's payload and other statistics. 

	if (verbose == 1) {
		printf("\nPrinting payload and other statistics... \n");
		static int count = 0;
		printf("Packet Count: %d\n", ++count);
		printf("Size of Packet: %d\n", pkthdr->len);
		printf("Payload: \n");
		for (int i = 0; i < pkthdr->len;i++) {
			if (isprint(packet[i])) {
				printf("%c", packet[i]);
			} else {
				printf(" . ", packet[i]);
			}

			if ((i%16==0 && i != 0) || i == pkthdr->len-1) {
				printf("\n");
			}
		}
		printf("-----------------------------------------\n");
  }
}

void show_warning_window(char* sourceIP) {
  char text[256];
  char command[256];
  snprintf(text, sizeof(text), "Warning: Suspect NMAP scan coming from the source IP: %s", sourceIP);
  snprintf(command, sizeof(command), "zenity --warning --text='%s'", text);
  if (system(command)==-1) {
    printf("Error making window.");
  }
}

int main(int argc, int *argv[]) {

	//printf("Starting...\n");

	//interface that program should sniff packets on
	char *device = "wlan0";
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;

	// modes: 0 is quiet, 1 is verbose
	int mode = 0;
	if (argc > 1) {
		if (strcmp(argv[1], "-v") == 0) {
			mode = 1;
		}
	}
	Loop_args l_args = {mode};
	if (mode == 1) printf("device: %s \n", device);;
	// sleep(5);

	// for filter
	struct bpf_program fp; 

	// for device and subnet / mask
	bpf_u_int32 maskp, netp; 


	// Looking up device and subnet / mask
	if (mode == 1) printf("About to pcap_lookupnet... \n");
	pcap_lookupnet(device, &netp, &maskp, errbuf);



	// Opening device to sniff
	if (mode == 1) printf("About to pcap_open_live.... \n");
	descr = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
	if (descr == NULL) {
		if (mode == 1) fprintf(stderr, "Can't open device %s. %s \n", device, errbuf);
		return 1;
	}
    
    //Setting up a filter with tcp. Can also set up for TCP, UDP, etc.
	if (mode == 1) printf("About to pcap_compile... \n");
	pcap_compile(descr, &fp, "tcp", 0, netp);
	if (mode == 1) printf("About to pcap_setfilter... \n");
	pcap_setfilter(descr, &fp);

	if (mode == 1) printf("Entering pcap_loop... \n");
	pcap_loop(descr, -1, callback_function, (u_char *)&l_args);

	return 0;
}


