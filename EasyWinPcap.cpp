#include <iostream>
#include "utils.h"
#include "InterfaceList.h"

int main()
{
	InterfaceList devices;
	devices.print();

	devices.setFilter(1, "ip and tcp");


	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	devices.startLoopListener(1);

	return 0;
}