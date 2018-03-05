#ifndef HAVE_DEAUTH_H
#define HAVE_DEAUTH_H

#include "attacks.h"

#define DEAUTH_MODE 'd'

enum blacklist_type{
	BLACKLIST_FROM_NONE,
	BLACKLIST_FROM_FILE,
	BLACKLIST_FROM_ESSID,
	BLACKLIST_FROM_BSSID,
	BLACKLIST_FROM_STATION
	
};


struct deauth_options {
  char *greylist;
  enum blacklist_type isblacklist;
  unsigned int speed;
  int stealth;
};

void deauth_shorthelp();

void deauth_longhelp();

struct attacks load_deauth();

void *deauth_parse(int argc, char *argv[]);

struct packet deauth_getpacket(void *options);

void deauth_print_stats(void *options);

void deauth_perform_check(void *options);

struct ether_addr get_target_bssid();

#endif