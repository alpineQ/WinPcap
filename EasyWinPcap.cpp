#include <iostream>
#include <map>
#include "utils.h"
#include "InterfaceList.h"

int main()
{
	std::map<ip_address, mac_address> commutationTable;
	int nDevice;
	InterfaceList devices;
	devices.print();
	std::cout << "Choose interface 0-" << devices.getSize() - 1 << ": ";
	std::cin >> nDevice;

	devices.startLoopListener(nDevice);

	return 0;
}