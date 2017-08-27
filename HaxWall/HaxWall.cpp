// HaxWall: HaxBall firewall for Windows

#include "stdafx.h"

#define BLOCK_DATA_CENTERS // uncomment flag when compiling flavors

#include "ban.h"
#include "PacketFilter.h"
#include <Winsock2.h>
#include <Mstcpip.h>
#include <Iphlpapi.h>
#include <Ws2tcpip.h>
#include <cstdint>
#include <iostream>
#include <list>
#include "haxball_whitelist.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

PacketFilter pktFilter;

void ListIpAddresses(std::list<SOCKADDR_IN> &list)
{
	IP_ADAPTER_ADDRESSES adapter_addresses[0xFF];
	DWORD adapter_addresses_buffer_size = sizeof(adapter_addresses);

	DWORD error = ::GetAdaptersAddresses(
		AF_INET,
		GAA_FLAG_SKIP_ANYCAST |
		GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_SKIP_FRIENDLY_NAME,
		NULL,
		adapter_addresses,
		&adapter_addresses_buffer_size);
	
	if (error != ERROR_SUCCESS)
	{
		return;
	}

	// Iterate through all of the adapters
	for (IP_ADAPTER_ADDRESSES* adapter = adapter_addresses; NULL != adapter; adapter = adapter->Next)
	{
		// Skip loopback adapters
		if (IF_TYPE_SOFTWARE_LOOPBACK == adapter->IfType)
		{
			continue;
		}

		// Parse all IPv4 and IPv6 addresses
		for (
			IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;
			NULL != address;
			address = address->Next)
		{
			auto family = address->Address.lpSockaddr->sa_family;
			if (AF_INET == family)
			{
				SOCKADDR_IN* ipv4 = reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr);
				list.push_back(*ipv4);
			}
		}
	}
}

void ban(uint32_t saddr)
{
	char buf[INET_ADDRSTRLEN];
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", (saddr >> 24) & 0xFF, (saddr >> 16) & 0xFF,
		(saddr >> 8) & 0xFF, saddr & 0xFF);
	pktFilter.Block(buf);
}

void unban(uint32_t saddr)
{
	char buf[INET_ADDRSTRLEN];
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", (saddr >> 24) & 0xFF, (saddr >> 16) & 0xFF,
		(saddr >> 8) & 0xFF, saddr & 0xFF);
	pktFilter.Unblock(buf);
}

BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
		case CTRL_C_EVENT:
			printf("Exiting...");
			pktFilter.StopFirewall();
			exit(0);
			return TRUE;
		default:
			break;
	}
	return FALSE;
}

int main()
{
	// Start firewall.
	if (pktFilter.StartFirewall())
	{
		std::cout << "Packet filter started successfully..." << std::endl;
	}
	else
	{
		std::cerr << "Error starting packet filter: " << GetLastError() << std::endl;
		exit(1);
	}

	if (!SetConsoleCtrlHandler(ConsoleHandlerRoutine, TRUE))
	{
		std::cerr << "Failed to set exit handler." << std::endl;
	}

	WSAData wsa = { 0 };
	WSAStartup(MAKEWORD(2, 2), &wsa);

	std::list<SOCKADDR_IN> bind_addrs;
	ListIpAddresses(bind_addrs);
	if (bind_addrs.size() == 0)
	{
		std::cerr << "Failed to find interface addresses" << std::endl;
		exit(1);
	}

	FD_SET socket_set;
	FD_ZERO(&socket_set);
	bool bound = false;
	std::list<SOCKET> sockets;
	for (auto it = bind_addrs.begin(); it != bind_addrs.end(); it++)
	{
		SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
		if (sock != INVALID_SOCKET)
		{
			if (bind(sock, (struct sockaddr*)&*it, sizeof(SOCKADDR_IN)) != 0)
			{
				std::cerr << "Failed to bind socket: " << WSAGetLastError() << std::endl;
				continue;
			}
			unsigned int opt = RCVALL_IPLEVEL;
			DWORD ret;
			if (WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), 0, 0, &ret, 0, 0) != 0)
			{
				std::cerr << "Failed to enable promiscuous mode: " << WSAGetLastError() << std::endl;
				continue;
			}
			FD_SET(sock, &socket_set);
			sockets.push_back(sock);
			bound = true;
		}
	}

	if (!bound)
	{
		std::cerr << "Failed to listen on any interface" << std::endl;
		exit(1);
	}
	
	unsigned char data[0xFFFF];

	AttackFirewall fw(ban, unban);

#ifdef BLOCK_DATA_CENTERS
	std::cout << "Data center blacklisting enabled." << std::endl;
	fw.SetBlacklist(&DataCenters, &HaxBallMatcher);
#else
	std::cout << "Data center blacklisting disabled." << std::endl;
#endif

	std::cout << "Firewall started. Keep this window open." << std::endl << std::endl;
	while (1)
	{
		if (select(0, &socket_set, NULL, NULL, NULL) == SOCKET_ERROR)
		{
			std::cerr << "Error: Select failed. " << WSAGetLastError() << std::endl;
			exit(1);
		}
		for (auto it = sockets.begin(); it != sockets.end(); it++)
		{
			if (!FD_ISSET(*it, &socket_set))
			{
				continue;
			}
			int count = recvfrom(*it, (char *)data, sizeof(data), 0, NULL, NULL);
			if (count != -1)
			{
				if (count < 28 || data[9] != 0x11) // Must be IP header with UDP payload
				{
					continue;
				}

				uint32_t saddr = ntohl(*((uint32_t*)(data + 12)));
				uint32_t daddr = ntohl(*((uint32_t*)(data + 16)));
				uint16_t sport = ntohs(*((uint16_t*)(data + 20)));
				uint16_t dport = ntohs(*((uint16_t*)(data + 22)));

				fw.ReceivePacket(saddr, sport);
				fw.ClearOldEntries();
			}
			else
			{
				std::cerr << "An error occured." << std::endl;
				return 1;
			}
		}
	}
    return 0;
}

