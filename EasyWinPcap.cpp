#include <iostream>
#include "utils.h"
#include "InterfaceList.h"

int main()
{
	int nDevice;
	InterfaceList devices;
	devices.print();
	std::cout << "Choose interface 0-" << devices.getSize() - 1 << ": ";
	std::cin >> nDevice;

	devices.startLoopListener(nDevice);

	return 0;
}