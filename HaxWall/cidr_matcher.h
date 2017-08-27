#include <cstdint>
#include <unordered_set>

typedef struct CIDR_S
{
	uint32_t network;
	uint8_t prefix;
	
	bool operator==(const CIDR_S &other) const
	{
		return network == other.network && prefix == other.prefix;
	}
} CIDR;

namespace std
{
	template <> struct hash<CIDR_S>
	{
		std::size_t operator()(const CIDR_S& k) const
		{
			return (hash<uint32_t>()(k.network)) ^ (hash<uint8_t>()(k.prefix));
		}
	};
}


#include "data_centers.h"

class CIDRMatcher
{
private:
	std::unordered_set<CIDR> cidrs;

public:
	CIDRMatcher(CIDR* networks, int count)
	{
		cidrs.reserve(count);
		for(int i = 0; i < count; i++)
		{
			cidrs.insert(networks[i]);
		}
	}

	bool Contains(uint32_t address)
	{
		CIDR cidr;
		cidr.network = address;
		cidr.prefix = 32;
		for(int i = 0; i < 33; i++)
		{
			if(i != 0)
			{
				cidr.network &= ~(1 << (i - 1));
			}
			cidr.prefix = (i == 33 ? 0 : (32 - i));

			auto result = cidrs.find(cidr);
			if(result != cidrs.end())
			{
				return true;
			}
		}
		return false;
	}
};

CIDRMatcher DataCenters(data_centers, sizeof(data_centers) / sizeof(data_centers[0]));
