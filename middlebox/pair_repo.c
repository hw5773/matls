#include "pair_repo.h"
#include "mb_log.h"

struct hash_table pair_table;

int init_repo_table()
{
  hash_table_init(&pair_table, 10, NULL);
  return 1;
}

int free_repo_table()
{
  hash_table_finit(&pair_table);
  return 1;
}

int add_pair_to_table(struct pair_entry *tmp)
{
  unsigned char key[16];

  MB_LOG("Add the pair into the table");

  memcpy(key, &(tmp->saddr), sizeof(uint32_t));
  memcpy(key + sizeof(uint32_t), &(tmp->sport), sizeof(uint16_t));
  memcpy(key + sizeof(uint32_t) + sizeof(uint16_t), &(tmp->daddr), sizeof(uint32_t));
  memcpy(key + 2 * sizeof(uint32_t) + sizeof(uint16_t), &(tmp->dport), sizeof(uint16_t));

  hash_table_insert(&pair_table, &tmp->entry, key, sizeof(key));

  MB_LOG("Add the pair complete");

  return 1;

out:
  return -1;
}

struct pair_entry *get_pair_from_table(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
  struct pair_entry *ret;
  struct hash_entry *hentry;

  unsigned char key[16];
  memcpy(key, &saddr, sizeof(uint32_t));
  memcpy(key + sizeof(uint32_t), &sport, sizeof(uint16_t));
  memcpy(key + sizeof(uint32_t) + sizeof(uint16_t), &daddr, sizeof(uint32_t));
  memcpy(key + 2 * sizeof(uint32_t) + sizeof(uint16_t), &dport, sizeof(uint16_t));

  if (!(hentry = hash_table_lookup_key(&pair_table, key, sizeof(key)))) goto out;
  
  ret = hash_entry(hentry, struct pair_entry, entry);

  return ret;

out:
  return NULL;
}

int free_pair_from_table(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
  unsigned char key[16];
  memcpy(key, &saddr, sizeof(uint32_t));
  memcpy(key + sizeof(uint32_t), &sport, sizeof(uint16_t));
  memcpy(key + sizeof(uint32_t) + sizeof(uint16_t), &daddr, sizeof(uint32_t));
  memcpy(key + 2 * sizeof(uint32_t) + sizeof(uint16_t), &dport, sizeof(uint16_t));

  if (!hash_table_del_key(&pair_table, key, sizeof(key))) goto out;

  return 1;

out:
  return -1;
}
