#include "utils.h"

char* iptos(u_long uAddress)
{
	static char output[IP_ADDRESS_LENGTH];
	u_char* p;

	p = (u_char*)&uAddress;
	_snprintf_s(output, IP_ADDRESS_LENGTH, sizeof(output), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output;
}

char* iptos(ip_address ip) {
	static char output[IP_ADDRESS_LENGTH + 6];

	_snprintf_s(output, IP_ADDRESS_LENGTH + 6, sizeof(output), "%d.%d.%d.%d", ip.byte1, ip.byte2, ip.byte3, ip.byte4);
	return output;
}

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	if (getnameinfo(sockaddr,
		sizeof(struct sockaddr_in6),
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

char* mactos(u_char mac[6]) {
	static char sMAC[18];
	snprintf(sMAC, 18, "%X:%X:%X:%X:%X:%X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return sMAC;
}

char* getTimeStamp(const struct pcap_pkthdr* header, bool includeMilliSeconds = false) {
	static char timestr[16];
	struct tm ltime;
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
	if (includeMilliSeconds)
		snprintf(timestr, 16, "%s:%.6d", (const char*)timestr, header->ts.tv_usec);

	return timestr;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	static unsigned nPacket = 0;
	ethernet_header* eh;
	ip_header* ih;
	tcp_header* th;
	arp_header* ah;
	u_int ip_len;

	printf("Ethernet information\n");
	eh = (ethernet_header*)pkt_data;
	printf("\tPacket number: %u\n", ++nPacket);
	printf("\tSource MAC: %s\n", mactos(eh->srcMAC));
	printf("\tDestination MAC: %s\n", mactos(eh->destMAC));
	printf("\tEther type: ");
	switch (eh->etherType) {
	case ETHERTYPE_TCPIP:
		printf("IPv4\n");
		break;
	case ETHERTYPE_ARP:
		printf("ARP\n");
		break;
	default:
		printf("%hu\n", eh->etherType);
		break;
	}
	printf("\tPacket length in bytes: %u\n", header->len);

	

	if (eh->etherType == ETHERTYPE_ARP)
	{
		ah = (arp_header*)(pkt_data + sizeof(ethernet_header));

		printf("ARP information\n");
		printf("\tPacket type: %s\n", (ah->packetType == ARP_REQUEST) ? "request" : "response");
	}
	else {
		/* retireve the position of the ip header */
		ih = (ip_header*)(pkt_data + sizeof(ethernet_header));

		/* retireve the position of the tcp header */
		ip_len = (ih->ver_len & 0xf) * 4;
		th = (tcp_header*)((u_char*)ih + ip_len);

		/* print ip addresses and tcp ports */
		printf("IP information\n");
		printf("\tSource address: %s\n", iptos(ih->src));
		printf("\tDestination address: %s\n", iptos(ih->dest));
		printf("\tTime To Live: %u\n", ih->ttl);
		printf("\tProtocol: %u\n", ih->protocol);
		printf("\tLength: %hu\n", (ih->length >> 8) | (ih->length & 0x00FF));// Из-за проблем с чтением little-endian big-endian

		printf("TCP information\n");
		printf("\tSource port: %hu\n", ntohs(th->srcPort));
		printf("\tDestination port: %hu\n", ntohs(th->destPort));
		printf("\tSN: %u\n", th->num);
		printf("\tAN: %u\n", th->ackNum);
		printf("\tACK: %s\n", ((th->flags & 0x10) ? "true" : "false"));
		printf("\tPSH: %s\n", ((th->flags & 0x8) ? "true" : "false"));
		printf("\tRST: %s\n", ((th->flags & 0x4) ? "true" : "false"));
		printf("\tSYN: %s\n", ((th->flags & 0x2) ? "true" : "false"));
		printf("\tFIN: %s\n", ((th->flags & 0x1) ? "true" : "false"));
		printf("\tWindow size: %hu\n", th->windowSize);
	}

	printf("\n");
}