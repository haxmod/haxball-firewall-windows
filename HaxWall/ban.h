#pragma once
// UDP Gaming Firewall

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define MAX_PORTS 6
#define TIMEOUT 180 // seconds
#define PURGE_INTERVAL 300 // seconds
#define MAX_PACKETS 80
#define MAX_PACKET_FRAME 1 // seconds
#define BAN_LENGTH_MULTIPORT 600 // seconds
#define BAN_LENGTH_FLOOD 600 // seconds

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