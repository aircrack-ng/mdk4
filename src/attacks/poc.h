#ifndef _POC_H
#define _POC_H

#include "../packet.h"
#include "attacks.h"

#define POC_MODE 'x'

struct poc_options {
  char vendor[255];
  struct ether_addr ap_mac;
  struct ether_addr sta_mac;
  unsigned int speed;

};

struct poc_packet{
    char vendor[255];
    int pkt_cnt;
    struct packet *pkts;
};

struct attacks load_poc();

#endif