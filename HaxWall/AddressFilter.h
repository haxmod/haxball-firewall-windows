#pragma once

#include <Winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <fwpmu.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")

class AddressFilter
{
private:
	HANDLE handle;
public:
	AddressFilter()
	{
		handle = NULL;

	}
};