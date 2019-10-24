#pragma once

#define HAVE_REMOTE
#define WIN32
#include <pcap.h>
#include "utils.h"

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
	void startLoopListener(unsigned nDevice, pcap_handler = packet_handler);


	void setFilter(unsigned nDevice, const char * filter);
};

