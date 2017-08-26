// HaxWall: HaxBall firewall for Windows

#include "stdafx.h"
#include "ban.h"
#include "PacketFilter.h"
#include <Winsock2.h>
#include <Mstcpip.h>
#include <iostream>
#include <list>
#include <Iphlpapi.h>
#include <Ws2tcpip.h>
#include <cstdint>
#include <signal.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

PacketFilter pktFilter;

void ListIpAddresses(std::list<SOCKADDR_IN*> &list)
{
	IP_ADAPTER_ADDRESSES* adapter_addresses(NULL);
	IP_ADAPTER_ADDRESSES* adapter(NULL);

	// Start with a 16 KB buffer and resize if needed -
	// multiple attempts in case interfaces change while
	// we are in the middle of querying them.
	DWORD adapter_addresses_buffer_size = 16 * 1024;
	for (int attempts = 0; attempts != 3; ++attempts)
	{
		adapter_addresses = (IP_ADAPTER_ADDRESSES*)malloc(adapter_addresses_buffer_size);

		DWORD error = ::GetAdaptersAddresses(
			AF_INET,
			GAA_FLAG_SKIP_ANYCAST |
			GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_DNS_SERVER |
			GAA_FLAG_SKIP_FRIENDLY_NAME,
			NULL,
			adapter_addresses,
			&adapter_addresses_buffer_size);

		if (ERROR_SUCCESS == error)
		{
			// We're done here, people!
			break;
		}
		else if (ERROR_BUFFER_OVERFLOW == error)
		{
			// Try again with the new size
			free(adapter_addresses);
			adapter_addresses = NULL;

			continue;
		}
		else
		{
			// Unexpected error code - log and throw
			free(adapter_addresses);
			adapter_addresses = NULL;
			exit(1);
		}
	}

	// Iterate through all of the adapters
	for (adapter = adapter_addresses; NULL != adapter; adapter = adapter->Next)
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
				// IPv4
				SOCKADDR_IN* ipv4 = reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr);
				list.push_back(ipv4);
			}
			else
			{
				// Skip all other types of addresses
				continue;
			}
		}
	}

	// Cleanup
	free(adapter_addresses);
	adapter_addresses = NULL;
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
		printf("Packet filter started successfully...\n");
	}
	else
	{
		printf("Error starting packet filter. GetLastError() 0x%x", ::GetLastError());
		exit(1);
	}

	if (!SetConsoleCtrlHandler(ConsoleHandlerRoutine, TRUE))
	{
		perror("Failed to set exit handler.");
	}

	WSAData wsa = { 0 };
	WSAStartup(MAKEWORD(2, 2), &wsa);

	std::list<SOCKADDR_IN*> bind_addrs;
	ListIpAddresses(bind_addrs);
	if (bind_addrs.size() == 0)
	{
		puts("Failed to find interface addresses");
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
			if (bind(sock, (struct sockaddr*)*it, sizeof(SOCKADDR_IN)) != 0)
			{
				perror("Failed to bind socket");
				continue;
			}
			unsigned int opt = RCVALL_IPLEVEL;
			DWORD ret;
			if (WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), 0, 0, &ret, 0, 0) != 0)
			{
				perror("Failed to enable promiscuous mode.");
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

	std::cout << "Firewall started. Keep this window open." << std::endl;
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
				std::cout << "An error occured." << std::endl;
				return 1;
			}
		}
	}
    return 0;
}

