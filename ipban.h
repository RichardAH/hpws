#ifndef HPWS_IPBAN
#define HPWS_IPBAN

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#define __IPBAN_SLOT_COUNT 100
#define __IPBAN_V4 1
#define __IPBAN_V6 2

union _ipban_addr
{
    uint32_t ipv4;
    uint32_t ipv6[4];
};
struct __ipban_slot
{
    uint8_t type;  // 0 = none, 1 = ipv4, 2 = ipv6
    time_t expire; // Epoch seconds at which the ip ban will expire.
    union _ipban_addr addr;
};

static struct __ipban_slot __ipbans[__IPBAN_SLOT_COUNT];
static int __ipban_filled_boundry = 0; // Indicates the last slot that has been touched.

/**
 * @return Pointer if found. NULL if not found/expired.
 */
struct __ipban_slot *__ipban_find(const uint32_t *addr, const uint8_t type)
{
    struct __ipban_slot *found = NULL;

    if (type == __IPBAN_V4)
    {
        for (int i = 0; i < __ipban_filled_boundry; i++)
        {
            struct __ipban_slot *slot = &__ipbans[i];
            if (slot->type == type &&
                slot->addr.ipv4 == *addr)
            {
                found = slot;
                break;
            }
        }
    }
    else
    {
        for (int i = 0; i < __ipban_filled_boundry; i++)
        {
            struct __ipban_slot *slot = &__ipbans[i];
            if (slot->type == type &&
                slot->addr.ipv6[0] == addr[0] &&
                slot->addr.ipv6[1] == addr[1] &&
                slot->addr.ipv6[2] == addr[2] &&
                slot->addr.ipv6[3] == addr[3])
            {
                found = slot;
                break;
            }
        }
    }

    // If the slot we found has expired, clean it up.
    if (found && found->expire <= time(NULL))
    {
        found->type = 0; // Mark the slot as vacant.
        found = NULL;
    }

    return found;
}

/**
 * @return 0 if success. -1 if failure (due to all slots being filled).
 */
int __ipban_ban(const uint32_t *addr, const uint32_t ttl_sec, const uint8_t type)
{
    // Check if already exists.
    struct __ipban_slot *slot = __ipban_find(addr, type);
    if (!slot) // If not existing, find first vacant slot.
    {
        for (int i = 0; i < __IPBAN_SLOT_COUNT; i++)
        {
            if (__ipbans[i].type == 0)
            {
                slot = &__ipbans[i];
                if (__ipban_filled_boundry < i + 1)
                    __ipban_filled_boundry = i + 1;
                break;
            }
        }
    }

    if (slot)
    {
        slot->type = type;
        slot->expire = time(NULL) + ttl_sec;

        if (type == __IPBAN_V4)
        {
            slot->addr.ipv4 = *addr;
        }
        else
        {
            slot->addr.ipv6[0] = addr[0];
            slot->addr.ipv6[1] = addr[1];
            slot->addr.ipv6[2] = addr[2];
            slot->addr.ipv6[3] = addr[3];
        }

        return 0;
    }

    return -1;
}

void __ipban_unban(const uint32_t *addr, const uint8_t type)
{
    struct __ipban_slot *slot = __ipban_find(addr, type);
    if (slot)
        slot->type = 0;
}

// Public interface-------------------------

int ipban_ban_v4(const uint32_t addr, const uint32_t ttl_sec)
{
    return __ipban_ban(&addr, ttl_sec, __IPBAN_V4);
}

int ipban_ban_v6(const uint32_t *addr, const uint32_t ttl_sec)
{
    return __ipban_ban(addr, ttl_sec, __IPBAN_V6);
}

bool ipban_unban_v4(const uint32_t addr)
{
    __ipban_unban(&addr, __IPBAN_V4);
}

int ipban_unban_v6(const uint32_t *addr)
{
    __ipban_unban(addr, __IPBAN_V6);
}

bool ipban_banned_v4(const uint32_t addr)
{
    return __ipban_find(&addr, __IPBAN_V4) != NULL;
}

bool ipban_banned_v6(const uint32_t *addr)
{
    return __ipban_find(addr, __IPBAN_V6) != NULL;
}

#endif