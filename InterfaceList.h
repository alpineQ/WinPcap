#pragma once

#define HAVE_REMOTE
#include <pcap.h>

class InterfaceList
{
	pcap_if_t* devicesList;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned size;

public:

	InterfaceList();
	~InterfaceList();

	void print();
	void print(unsigned nDevice);
	void printMore();

	pcap_if_t* get(unsigned);
	unsigned getSize();
	void clear();

	pcap_t* openDevice(unsigned nDevice);
	int startLoopListener(unsigned nDevice, pcap_handler);

	void setFilter(unsigned nDevice, const char * filter);
};

