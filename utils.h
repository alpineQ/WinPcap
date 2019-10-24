#pragma once

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "ws2_32.lib") // For getnameinfo()

#define HAVE_REMOTE
#define WIN32
#include <pcap.h>
#include <winsock.h>

#define IP_ADDRESS_LENGTH 16
#define ETHERTYPE_ARP 0x0608
#define ETHERTYPE_TCPIP 0x0008
#define ARP_REQUEST 0x0100

typedef struct ethernet_header {
	u_char destMAC[6];
	u_char srcMAC[6];
	u_short etherType;
}ethernet_header;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_len;        // Version (4 bits) + Internet header length (4 bits)
    u_char  serviceType;            // Type of service 
    u_short length;           // Total length 
    u_short identification; // Identification
    u_short flags_offset;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  protocol;          // Protocol
    u_short checkSum;            // Header checksum
    ip_address  src;      // Source address
    ip_address  dest;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP header*/
typedef struct tcp_header {
	u_short srcPort;
	u_short destPort;
	u_int num;
	u_int ackNum;
	u_short flags;
	u_short windowSize;
} tcp_header;

typedef struct arp_header {
	u_short hardware;
	u_short protocol;
	u_char protoSize;
	u_char hardwareSize;
	u_short packetType;
} arp_header;

char* iptos(u_long uAddress);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);