#ifndef __PAIR_REPO__
#define __PAIR_REPO__

#include "hash_table.h"
#include <stdint.h>

struct pair_entry
{
  uint32_t saddr;
  uint16_t sport;
  uint32_t daddr;
  uint16_t dport;

  uint32_t seq; // influxed source's sequence
  uint32_t ack; // influxed source's acknowledge

  struct hash_entry entry;
};

int init_repo_table();
int free_repo_table();
int add_pair_to_table(struct pair_entry *tmp);
struct pair_entry *get_pair_from_table(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
int free_pair_from_table(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);

#endif /* pair_repo.h */
