#include <iostream>
#include "utils.h"

char* iptos(u_long uAddress)
{
	static char output[IP_ADDRESS_LENGTH];
	u_char* p;

	p = (u_char*)&uAddress;
	snprintf(output, IP_ADDRESS_LENGTH, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output;
}

char* iptos(ip_address ip) {
	static char output[IP_ADDRESS_LENGTH];

	snprintf(output, IP_ADDRESS_LENGTH, "%d.%d.%d.%d", ip.byte1, ip.byte2, ip.byte3, ip.byte4);
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

char* mactos(mac_address mac) {
	static char sMAC[18];
	snprintf(sMAC, 18, "%X:%X:%X:%X:%X:%X", mac.byte1, mac.byte2, mac.byte3, mac.byte4, mac.byte5, mac.byte6);
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

	std::cout << "Ethernet information" << std::endl;
	eh = (ethernet_header*)pkt_data;
	std::cout << "\tPacket number: " << ++nPacket << std::endl
		<< "\tSource MAC: " << mactos(eh->srcMAC) << std::endl
		<< "\tDestination MAC: " << mactos(eh->destMAC) << std::endl
		<< "\tEther type: ";
	switch (eh->etherType) {
	case ETHERTYPE_TCPIP:
		std::cout << "IPv4" << std::endl;
		break;
	case ETHERTYPE_ARP:
		std::cout << "ARP" << std::endl;
		break;
	default:
		std::cout << eh->etherType << std::endl;
		break;
	}
	std::cout << "\tPacket length in bytes: " << header->len << std::endl;

	switch (eh->etherType) {
	case ETHERTYPE_ARP: {
		arp_header* ah = (arp_header*)(pkt_data + sizeof(ethernet_header));

		std::cout << "ARP information" << std::endl
			<< "\tPacket type: " << ((ah->packetType == ARP_REQUEST) ? "request" : "reply") << std::endl
			<< "\tSource MAC: " << mactos(ah->srcMAC) << std::endl
			<< "\tSource IP: " << iptos(ah->srcIP) << std::endl
			<< "\tDest MAC: " << mactos(ah->destMAC) << std::endl
			<< "\tDest IP: " << iptos(ah->destIP) << std::endl;

		break;
	}
	case ETHERTYPE_TCPIP: {
		/* retireve the position of the ip header */
		ip_header* ih = (ip_header*)(pkt_data + sizeof(ethernet_header));

		/* retireve the position of the tcp header */
		u_int ip_len = (ih->ver_len & 0xf) * 4;
		tcp_header* th = (tcp_header*)((u_char*)ih + ip_len);

		/* print ip addresses and tcp ports */
		std::cout << "IP information" << std::endl
			<< "\tSource address: " << iptos(ih->src) << std::endl
			<< "\tDestination address: " << iptos(ih->dest) << std::endl
			<< "\tTime To Live: " << ih->ttl << std::endl
			<< "\tProtocol: " << ih->protocol << std::endl
			<< "\tLength: " << htons(ih->length);

		std::cout << "TCP information" << std::endl
			<< "\tSource port: " << ntohs(th->srcPort) << std::endl
			<< "\tDestination port: " << ntohs(th->destPort) << std::endl
			<< "\tSN: " << th->num << std::endl
			<< "\tAN: " << th->ackNum << std::endl
			<< "\tACK: " << ((th->flags & 0x16) ? "true" : "false") << std::endl
			<< "\tPSH: " << ((th->flags & 0x8) ? "true" : "false") << std::endl
			<< "\tRST: " << ((th->flags & 0x4) ? "true" : "false") << std::endl
			<< "\tSYN: " << ((th->flags & 0x2) ? "true" : "false") << std::endl
			<< "\tFIN: " << ((th->flags & 0x1) ? "true" : "false") << std::endl
			<< "\tWindow size: " << th->windowSize << std::endl;
		break;
	}
	default:
		break;
	}
	std::cout << std::endl;
}