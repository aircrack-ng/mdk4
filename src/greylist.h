#ifndef HAVE_GREYLIST_H
#define HAVE_GREYLIST_H

#include "mac_addr.h"

//Loads or appends to list of mac addresses.
//to change list type, use filename NULL

void load_blacklist(char *filename);

void load_whitelist(char *filename);

char is_blacklisted(struct ether_addr mac);

char is_whitelisted(struct ether_addr mac);

#endif
