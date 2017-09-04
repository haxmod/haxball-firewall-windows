#pragma once
// UDP Gaming Firewall

#include <cstdint>
#include <ctime>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include "cidr_matcher.h"

#define MAX_PORTS 3 // maximum number of source ports per client
#define TIMEOUT 180 // seconds
#define PURGE_INTERVAL 3600 // seconds
#define MAX_PACKETS 80 // per packet frame span (defined below)
#define MAX_PACKET_FRAME 1 // seconds
#define BAN_DURATION_MULTIPORT 300 // seconds
#define BAN_DURATION_FLOOD 300 // seconds
#define BAN_DURATION_BLACKLIST 3600 // seconds

// On Windows, the purge interval defines the minimum ban durations because packets from
// banned IP addresses are no longer received

static time_t now;

struct AddressStatistics
{
public:
	time_t times[MAX_PACKETS];
	size_t packet_count;
	size_t last_time;
	std::unordered_map<uint16_t, time_t> ports;

	AddressStatistics(uint16_t port)
	{
		Reset(port);
	}

	void RemoveOldPorts()
	{
		for (auto it = ports.begin();  it != ports.end();)
		{
			double elapsed = difftime(now, it->second);
			if (elapsed > TIMEOUT)
			{
				it = ports.erase(it);
				continue;
			}
			it++;
		}
	}

	void Reset(uint16_t port)
	{
		packet_count = 1;
		ports.clear();
		last_time = 0;
		times[last_time] = now;
		ports.insert(std::make_pair(port, now));
	}

	bool TimedOut()
	{
		double elapsed = difftime(now, times[last_time]);
		return elapsed > TIMEOUT;
	}

	void CountPacket()
	{
		packet_count++;
		if (++last_time >= MAX_PACKETS)
		{
			last_time = 0;
		}
		times[last_time] = now;
	}

	bool HitLimit()
	{
		size_t first_time = last_time + 1;
		if (first_time >= MAX_PACKETS)
		{
			first_time = 0;
		}
		double diff = difftime(times[last_time], times[first_time]);
		return packet_count > MAX_PACKETS && diff < MAX_PACKET_FRAME;
	}
};

enum class BanStatus {
	Unbanned,
	Banned,
	Ban,
	Unban
};

struct BanInfo
{
	time_t expiry;

public:
	BanInfo(time_t duration)
	{
		expiry = now + duration;
	}

	bool TimedOut()
	{
		double elapsed = difftime(now, expiry);
		return elapsed >= 0;
	}
};

class AttackFirewall
{
private:
	std::unordered_map<uint32_t, AddressStatistics> table;
	std::unordered_map<uint32_t, BanInfo> bans;
	time_t last_purge;
	void (*ban_function)(uint32_t);
	void(*unban_function)(uint32_t);
	CIDRMatcher *blacklist;
	CIDRMatcher *exceptions;
	std::ofstream out;

	void Log(const char *msg, uint32_t addr)
	{
		std::cout << msg << " " << ((addr >> 24) & 0xFF) << "." << ((addr >> 16) & 0xFF) << "." <<
			((addr >> 8) & 0xFF) << "." << (addr & 0xFF) << std::endl;
		if (out.is_open())
		{
			out << msg << " " << ((addr >> 24) & 0xFF) << "." << ((addr >> 16) & 0xFF) << "." <<
				((addr >> 8) & 0xFF) << "." << (addr & 0xFF) << std::endl;
		}
	}

	bool IsSpecialAddress(uint32_t addr)
	{
		uint8_t b1, b2, b3, b4;
		b1 = (uint8_t)(addr >> 24);
		b2 = (uint8_t)((addr >> 16) & 0x0ff);
		b3 = (uint8_t)((addr >> 8) & 0x0ff);
		b4 = (uint8_t)(addr & 0x0ff);

		switch (b1)
		{
		case 0:
		case 10:
		case 127:
			return true;
		case 100:
			if (b2 >= 64 && b2 <= 127)
			{
				return true;
			}
			break;
		case 169:
			if (b2 == 254)
			{
				return true;
			}
			break;
		case 172:
			if (b2 >= 16 && b2 <= 32)
			{
				return true;
			}
			break;
		case 192:
			if (b2 == 0 && (b3 == 0 || b3 == 2)
				|| b2 == 88 && b3 == 99
				|| b2 == 168)
			{
				return true;
			}
			break;
		case 198:
			if (b2 >= 18 && b2 <= 19 || b2 == 51 && b3 == 100)
			{
				return true;
			}
			break;
		case 203:
			if (b2 == 0 && b3 == 113)
			{
				return true;
			}
		}
		if (b1 >= 224)
		{
			return true;
		}
		return false;
	}

public:
	AttackFirewall(void(*ban)(uint32_t) = NULL, void(*unban)(uint32_t) = NULL) : out("firewall.log", std::ios::out)
	{
		if (out.is_open())
		{
			std::cout << "Logging to firewall.log." << std::endl;
		}
		blacklist = NULL;
		exceptions = NULL;
		table.reserve(0xFFFF);
		bans.reserve(0xFFFF);
		last_purge = now;
		ban_function = ban;
		unban_function = unban;
	}

	void SetBlacklist(CIDRMatcher *pBlacklist = NULL, CIDRMatcher *pExceptions = NULL)
	{
		blacklist = pBlacklist;
		exceptions = pExceptions;
	}

	BanStatus ReceivePacket(uint32_t addr, uint16_t port)
	{
		time(&now);
		BanStatus result = BanStatus::Unbanned;
		if (IsSpecialAddress(addr))
		{
			return result;
		}
		auto ban = bans.find(addr);
		if (ban != bans.end())
		{
			if (ban->second.TimedOut())
			{
				Log("Unban:", addr);
				bans.erase(ban);
				if (unban_function != NULL)
				{
					unban_function(addr);
				}
				return BanStatus::Unban;
			}
			else
			{
				return BanStatus::Banned;
			}
		}

		auto entry = table.find(addr);
		if (entry == table.end())
		{
			if (blacklist && blacklist->Contains(addr) && (!exceptions || !exceptions->Contains(addr)))
			{
				bans.insert(std::make_pair(addr, BanInfo(BAN_DURATION_BLACKLIST)));
				if (ban_function != NULL)
				{
					ban_function(addr);
				}
				Log("Blacklist:", addr);
				return BanStatus::Ban;
			}
			Log("First packet:", addr);
			AddressStatistics entry(port);
			table.insert(std::make_pair(addr, entry));
			return BanStatus::Unbanned;
		}
		else
		{
			if (entry->second.TimedOut())
			{
				Log("Reappearance:", addr);
				entry->second.Reset(port);
				return BanStatus::Unbanned;
			}
			entry->second.RemoveOldPorts();
			if (entry->second.ports.size() > MAX_PORTS)
			{
				Log("Multiport:", addr);
				bans.insert(std::make_pair(addr, BanInfo(BAN_DURATION_MULTIPORT)));
				table.erase(entry);
				if (ban_function != NULL)
				{
					ban_function(addr);
				}
				return BanStatus::Ban;
			}
			entry->second.ports[port] = now;

			entry->second.CountPacket();
			if (entry->second.HitLimit())
			{
				bans.insert(std::make_pair(addr, BanInfo(BAN_DURATION_FLOOD)));
				table.erase(entry);
				if (ban_function != NULL)
				{
					ban_function(addr);
				}
				Log("Flood:", addr);
				return BanStatus::Ban;
			}
			return BanStatus::Unbanned;
		}
	}

	void ClearOldEntries()
	{
		time(&now);
		if(difftime(now, last_purge) <= PURGE_INTERVAL)
		{
			return;
		}
		for (auto it = table.begin(); it != table.end();)
		{
			if (it->second.TimedOut())
			{
				it = table.erase(it);
			}
			else
			{
				it++;
			}
		}

		for (auto it = bans.begin(); it != bans.end();)
		{
			if (unban_function != NULL)
			{
				unban_function(it->first);
			}
			if (it->second.TimedOut())
			{
				uint32_t addr = it->first;
				Log("Unban:", addr);
				it = bans.erase(it);
			}
			else
			{
				it++;
			}
		}
		last_purge = now;
	}

	~AttackFirewall()
	{
		if (out.is_open())
		{
			out.close();
		}
		for (auto it = bans.begin(); it != bans.end(); it++)
		{
			if (unban_function != NULL)
			{
				unban_function(it->first);
			}
		}
	}
};
