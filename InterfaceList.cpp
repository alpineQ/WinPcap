#include <iostream>
#include <string>
#include "InterfaceList.h"


InterfaceList::InterfaceList(bool collectAddresses)
{
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &devicesList, errbuf) == -1)
		throw std::runtime_error(std::string("Error in pcap_findalldevs_ex: ") + errbuf);
	collectCommutationTable = collectAddresses;
	size = 0;
	for (pcap_if_t* device = devicesList; device != NULL; device = device->next)
		++size;
};

InterfaceList::~InterfaceList()
{
	pcap_freealldevs(devicesList);
};

void InterfaceList::print()
{
	if (size == 0) {
		std::cout << "No interfaces found! Make sure WinPcap is installed." << std::endl;
		return;
	}
	int i = 0;
	for (pcap_if_t* device = devicesList; device != NULL; device = device->next, ++i)
		std::cout << i << ". " << ((device->description) ? device->description : "No description available") << std::endl;
};

void InterfaceList::print(unsigned nDevice)
{
	if (nDevice < 0 || nDevice > size - 1)
	{
		throw std::runtime_error("Interface number out of range.");
	}
	unsigned i = 0;
	for (pcap_if_t* device = devicesList; device != NULL && i < nDevice; device = device->next, ++i)
		if (i + 1 == nDevice)
			std::cout << ((device->description) ? device->description : "No description available") << std::endl;
};

void InterfaceList::printMore()
{
	pcap_addr_t* address;
	char ip6str[128];
	for (pcap_if_t* device = devicesList; device != NULL; device = device->next) {
		/* Name */
		std::cout << device->name << std::endl;

		/* Description */
		if (device->description)
			std::cout << "\tDescription: " << device->description << std::endl;

		/* Loopback Address*/
		std::cout << "\tLoopback: " << ((device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no") << std::endl;

		/* IP addresses */
		for (address = device->addresses; address; address = address->next) {
			std::cout << "\tAddress Family: #" << address->addr->sa_family << std::endl;

			switch (address->addr->sa_family)
			{
			case AF_INET:
				std::cout << "\tAddress Family Name: AF_INET" << std::endl;
				if (address->addr)
					std::cout << "\tAddress: " << iptos(((struct sockaddr_in*)address->addr)->sin_addr.s_addr) << std::endl;
				if (address->netmask)
					std::cout << "\tNetmask: %s\n" << iptos(((struct sockaddr_in*)address->netmask)->sin_addr.s_addr) << std::endl;
				if (address->broadaddr)
					std::cout << "\tBroadcast Address: %s\n" << iptos(((struct sockaddr_in*)address->broadaddr)->sin_addr.s_addr) << std::endl;
				if (address->dstaddr)
					std::cout << "\tDestination Address: %s\n" << iptos(((struct sockaddr_in*)address->dstaddr)->sin_addr.s_addr) << std::endl;
				break;

			case AF_INET6:
				std::cout << "\tAddress Family Name: AF_INET6" << std::endl;
				if (address->addr)
					std::cout << "\tAddress: " << ip6tos(address->addr, ip6str, sizeof(ip6str)) << std::endl;
				break;

			default:
				std::cout << "\tAddress Family Name: Unknown" << std::endl;
				break;
			}
		}
		std::cout << std::endl;
	}
}

unsigned InterfaceList::getSize()
{
	return size;
}

pcap_if_t* InterfaceList::get(unsigned nDevice)
{
	if (nDevice < 0 || nDevice > size - 1)
	{
		throw std::runtime_error("Interface number out of range.");
	}

	/* Jump to the selected adapter */
	pcap_if_t* device = devicesList;
	for (unsigned i = 0; i < nDevice; device = device->next, i++);

	return device;
}

pcap_t* InterfaceList::openDevice(unsigned nDevice)
{
	pcap_t* adhandle;
	if ((adhandle = pcap_open(get(nDevice)->name,          // name of the device
		100,//65536,            // portion of the packet to capture
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		throw std::runtime_error(std::string("Unable to open the adapter.") + get(nDevice)->name + " is not supported by WinPcap");
	}

	return adhandle;
}

void InterfaceList::startLoopListener(unsigned nDevice, pcap_handler packet_handler)
{
	pcap_t* adhandle = openDevice(nDevice);
	if (pcap_datalink(adhandle) != DLT_EN10MB)
		throw std::runtime_error("This program works only on Ethernet networks.");

	std::cout << std::endl << "Listening on " << get(nDevice)->description << "..." << std::endl << std::endl;
	pcap_loop(adhandle, 0, packet_handler, NULL);
}

void InterfaceList::sendPacket(unsigned nDevice, u_char* packet, int size)
{
	pcap_t* device = openDevice(nDevice);
	if (pcap_sendpacket(device, packet, 100) != NULL)
		std::cout << "Error sending the packet : " << pcap_geterr(device) << std::endl;
}

void InterfaceList::clear()
{
	pcap_freealldevs(devicesList);
}

void InterfaceList::setFilter(unsigned nDevice, const char* filter)
{
	u_long netmask;
	bpf_program filterCode;
	pcap_t* adhandle = openDevice(nDevice);
	if (get(nDevice)->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(get(nDevice)->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without an address we suppose to be in a C class network */
		netmask = 0xffffff;

	if (pcap_compile(adhandle, &filterCode, filter, 1, netmask) < 0)
		throw std::runtime_error("Unable to compile the packet filter. Check the syntax.");

	if (pcap_setfilter(adhandle, &filterCode) < 0)
		throw std::runtime_error("Error setting the filter.");
}