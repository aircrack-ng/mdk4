#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "greylist.h"
#include "helpers.h"

struct greylist {
  struct ether_addr mac;
  struct greylist *next;
};

typedef enum
{
  BLACK_LIST,
  WHITE_LIST,

}list_type;

struct greylist *glist = NULL;
struct blacklist *blist = NULL;
struct whitelist *wlist = NULL;

char black = 0;
char white = 0;


struct greylist *add_to_greylist(struct ether_addr new, struct greylist *glist) {
  struct greylist *gnew = malloc(sizeof(struct greylist));

  gnew->mac = new;

  if (glist) {
    gnew->next = glist->next;
    glist->next = gnew;
  } else {
    glist = gnew;
    gnew->next = gnew;
  }

  return glist;
}

struct greylist *search_in_greylist(struct ether_addr mac, struct greylist *glist) {
  struct greylist *first;

  if (! glist) return NULL;

  first = glist;
  do {
    if (MAC_MATCHES(mac, glist->mac)) {
      return glist;
    }
    glist = glist->next;
  } while (glist != first);

  return NULL;
}

void load_greylist(list_type type, char *filename) {
  char *entry;

  if (filename) {
    
    if(type == BLACK_LIST)
    {
      glist = blist;
      black = 1;
    }
    else if(type == WHITE_LIST)
    {
      glist = wlist;
      white = 1;
    }

    entry = read_next_line(filename, 1);
    while(entry) 
    {
      if (!search_in_greylist(parse_mac(entry), glist)) //Only add new entries
      {	
	      glist = add_to_greylist(parse_mac(entry), glist);
      }
      free(entry);
      entry = read_next_line(filename, 0);
    }
  }
}

void load_blacklist(char *filename)
{
  load_greylist(BLACK_LIST, filename);
}

void load_whitelist(char *filename)
{
  load_greylist(WHITE_LIST, filename);
}

char is_blacklisted(struct ether_addr mac) 
{
  struct greylist *entry; 

  if (black) 
  {
     entry = search_in_greylist(mac, blist);
    if (entry) 
      return 1;
  } 

  return 0;
}

char is_whitelisted(struct ether_addr mac) 
{
  struct greylist *entry; 

  if (white) 
  {
    entry = search_in_greylist(mac, wlist);

    if (entry) 
      return 1;
  } 

  return 0;
}
