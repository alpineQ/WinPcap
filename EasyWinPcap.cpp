#include <iostream>
#include "utils.h"
#include "InterfaceList.h"

int main()
{
	InterfaceList devices;
	devices.print();

	devices.setFilter(1, "ip and tcp");

	devices.startLoopListener(1, packet_handler);
	return 0;
}