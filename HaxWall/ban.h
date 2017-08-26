#pragma once
// UDP Gaming Firewall

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unordered_map>
#include <unordered_set>

#define MAX_PORTS 4
#define TIMEOUT 180 // seconds
#define PURGE_INTERVAL 300 // seconds
#define MAX_PACKETS 80 // per packet frame span (defined below)
#define MAX_PACKET_FRAME 1 // seconds
#define BAN_DURATION_MULTIPORT 300 // seconds
#define BAN_DURATION_FLOOD 300 // seconds

// On Windows, the purge interval defines the minimum ban durations because packets from
// banned IP addresses are no longer received

struct AddressStatistics
{
public:
	time_t times[MAX_PACKETS];
	size_t packet_count;
	time_t *last_time;
	std::unordered_map<uint16_t, time_t> ports;

	AddressStatistics(uint16_t port)
	{
		Reset(port);
	}

	void RemoveOldPorts()
	{
		time_t now;
		time(&now);
		
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
		ports.clear();
		time_t tm;
		time(&tm);
		ports.insert(std::make_pair(port, tm));
		last_time = &times[MAX_PACKETS - 1];
		time(last_time);
	}

	bool TimedOut()
	{
		time_t now;
		time(&now);
		double elapsed = difftime(now, *last_time);
		return elapsed > TIMEOUT;
	}

	void CountPacket()
	{
		packet_count++;
		if (++last_time >= times + MAX_PACKETS)
		{
			last_time = &times[0];
		}
		time(last_time);
	}

	bool HitLimit()
	{
		time_t *first_time = last_time + 1;
		if (first_time > &times[MAX_PACKETS - 1])
		{
			first_time = &times[0];
		}
		double diff = difftime(*last_time, *first_time);
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
		time(&expiry);
		expiry += duration;
	}

	bool TimedOut()
	{
		time_t now;
		time(&now);
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
	AttackFirewall(void(*ban)(uint32_t) = NULL, void(*unban)(uint32_t) = NULL)
	{
		table.reserve(0xFFFF);
		bans.reserve(0xFFFF);
		time(&last_purge);
		ban_function = ban;
		unban_function = unban;
	}

	BanStatus ReceivePacket(uint32_t addr, uint16_t port)
	{
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
				printf("Unban %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
					(addr >> 8) & 0xFF, addr & 0xFF);
				bans.erase(ban);
				if (unban_function != NULL)
				{
					unban_function(addr);
				}
				result = BanStatus::Unban;
			}
			else
			{
				return BanStatus::Banned;
			}
		}

		auto entry = table.find(addr);
		if (entry == table.end())
		{
			printf("First packet from %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
				(addr >> 8) & 0xFF, addr & 0xFF);
			AddressStatistics entry(port);
			table.insert(std::make_pair(addr, entry));
			return BanStatus::Unbanned;
		}
		else
		{
			if (entry->second.TimedOut())
			{
				printf("Reappearance of %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
					(addr >> 8) & 0xFF, addr & 0xFF);
				entry->second.Reset(port);
				return BanStatus::Unbanned;
			}
			entry->second.RemoveOldPorts();
			if (entry->second.ports.size() >= MAX_PORTS)
			{
				printf("Multiport attack from %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
					(addr >> 8) & 0xFF, addr & 0xFF);
				bans.insert(std::make_pair(addr, BanInfo(BAN_DURATION_MULTIPORT)));
				table.erase(entry);
				if (ban_function != NULL)
				{
					ban_function(addr);
				}
				return BanStatus::Ban;
			}
			time_t tm;
			time(&tm);
			entry->second.ports[port] = tm;

			entry->second.CountPacket();
			if (entry->second.HitLimit())
			{
				bans.insert(std::make_pair(addr, BanInfo(BAN_DURATION_FLOOD)));
				table.erase(entry);
				if (ban_function != NULL)
				{
					ban_function(addr);
				}
				printf("Flood from %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
					(addr >> 8) & 0xFF, addr & 0xFF);
				return BanStatus::Ban;
			}
		}
	}

	void ClearOldEntries()
	{
		time_t now;
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
				printf("Unban %d.%d.%d.%d.\n", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
					(addr >> 8) & 0xFF, addr & 0xFF);
				it = bans.erase(it);
			}
			else
			{
				it++;
			}
		}
		time(&last_purge);
	}

	~AttackFirewall()
	{
		for (auto it = bans.begin(); it != bans.end(); it++)
		{
			if (unban_function != NULL)
			{
				unban_function(it->first);
			}
		}
	}
};



//std::map<uint32_t, 

typedef struct entry
{
	uint32_t addr;
	uint16_t ports[MAX_PORTS];
	time_t ports_last[MAX_PORTS];
	time_t times[MAX_PACKETS];
	size_t packet_count;
	time_t *last_time;
	struct entry *next;
} entry_t;

static entry_t *table[65536];
static time_t last_purge;

typedef struct ban_entry
{
	uint32_t addr;
	time_t expiry;
	struct ban_entry *next;
} ban_entry_t;

static ban_entry_t *ban_table[65536];

entry_t* find_entry(uint32_t addr, entry_t **prev)
{
	size_t slot = addr % (sizeof(table) / sizeof(*table));
	entry_t *slot_entry = table[slot];
	if (prev != NULL)
	{
		*prev = NULL;
	}
	while (1)
	{
		if (slot_entry == NULL)
		{
			return NULL;
		}
		if (slot_entry->addr == addr)
		{
			return slot_entry;
		}
		if (prev != NULL)
		{
			*prev = slot_entry;
		}
		slot_entry = slot_entry->next;
	}
}

ban_entry_t *find_ban_entry(uint32_t addr, ban_entry_t **prev)
{
	size_t slot = addr % (sizeof(ban_table) / sizeof(*ban_table));
	ban_entry_t *slot_entry = ban_table[slot];
	if (prev != NULL)
	{
		*prev = NULL;
	}
	while (1)
	{
		if (slot_entry == NULL)
		{
			return NULL;
		}
		if (slot_entry->addr == addr)
		{
			return slot_entry;
		}
		if (prev != NULL)
		{
			*prev = slot_entry;
		}
		slot_entry = slot_entry->next;
	}
}

void initialize_entry(entry_t* entry, uint32_t addr, uint16_t port)
{
	memset(entry, 0, sizeof(*entry));
	entry->addr = addr;
	entry->ports[0] = port;
	time(&entry->ports_last[0]);
	entry->last_time = &entry->times[MAX_PACKETS - 1];
	time(entry->last_time);
}

void initialize_ban_entry(ban_entry_t *entry, uint32_t addr, time_t length)
{
	memset(entry, 0, sizeof(*entry));
	entry->addr = addr;
	time(&entry->expiry);
	entry->expiry += length;
}

void new_ban_entry(uint32_t addr, time_t length)
{
	size_t slot = addr % (sizeof(ban_table) / sizeof(*ban_table));
	ban_entry_t *slot_entry = ban_table[slot];
	if (slot_entry == NULL)
	{
		slot_entry = (ban_entry_t*)malloc(sizeof(*slot_entry));
		if (slot_entry == NULL) // Out of memory
		{
			return;
		}
		initialize_ban_entry(slot_entry, addr, length);
		if (ban_table[slot] == NULL)
		{
			ban_table[slot] = slot_entry;
		}
		else
		{
			slot_entry->next = ban_table[slot];
			ban_table[slot] = slot_entry;
		}
	}
}

int entry_hit_packet_limit(entry_t *entry)
{
	time_t *first_time = entry->last_time + 1;
	if (first_time > &entry->times[MAX_PACKETS - 1])
	{
		first_time = &entry->times[0];
	}
	double diff = difftime(*entry->last_time, *first_time);
	return entry->packet_count > MAX_PACKETS && diff < MAX_PACKET_FRAME;
}

void new_entry(uint32_t addr, uint16_t port)
{
	size_t slot = addr % (sizeof(table) / sizeof(*table));
	entry_t *slot_entry = table[slot];
	if (slot_entry == NULL)
	{
		slot_entry = (entry_t*)malloc(sizeof(*slot_entry));
		if (slot_entry == NULL) // Out of memory
		{
			return;
		}
		initialize_entry(slot_entry, addr, port);
		if (table[slot] == NULL)
		{
			table[slot] = slot_entry;
		}
		else
		{
			slot_entry->next = table[slot];
			table[slot] = slot_entry;
		}
	}
}

int timed_out(entry_t* entry)
{
	time_t now;
	time(&now);
	double elapsed = difftime(now, *entry->last_time);
	return elapsed > TIMEOUT;
}

int ban_timed_out(ban_entry_t* entry)
{
	time_t now;
	time(&now);
	double elapsed = difftime(now, entry->expiry);
	return elapsed > 0;
}

void purge_table()
{
	return;
	time_t now;
	time(&now);
	if (difftime(now, last_purge) > PURGE_INTERVAL)
	{
		for (size_t i = 0; i < sizeof(table) / sizeof(*table); i++)
		{
			entry_t *slot_entry = table[i];
			entry_t *prev = NULL;
			while (1)
			{
				if (slot_entry == NULL)
				{
					break;
				}
				if (timed_out(slot_entry))
				{
					if (prev == NULL)
					{
						free(slot_entry);
						table[i] = NULL;
					}
					else
					{
						prev->next = slot_entry->next;
						free(slot_entry);
					}
				}
				prev = slot_entry;
				slot_entry = slot_entry->next;
			}
		}
		for (size_t i = 0; i < sizeof(ban_table) / sizeof(*ban_table); i++)
		{
			ban_entry_t *slot_entry = ban_table[i];
			ban_entry_t *prev = NULL;
			while (1)
			{
				if (slot_entry == NULL)
				{
					break;
				}
				if (ban_timed_out(slot_entry))
				{
					if (prev == NULL)
					{
						free(slot_entry);
						ban_table[i] = NULL;
					}
					else
					{
						prev->next = slot_entry->next;
						free(slot_entry);
					}
				}
				prev = slot_entry;
				slot_entry = slot_entry->next;
			}
		}
		time(&last_purge);
	}
}