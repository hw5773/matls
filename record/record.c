/**
 * @file record.c
 * @author Hyunwoo Lee
 * @date 26 Feb 2018
 * @brief This file is to implement the functions to manipulate the
 * modification record
 */

#include "record.h"
#include "errors.h"
#include "logs.h"

/**
 * @brief Initialize the modification record
 * @param mr Data structure of the modification record
 * @param len Length of the MAC
 * @return SUCCESS(1)/FAILURE(0)
 */
int init_record(MOD_RECORD **mr, int len)
{
  APP_LOG("Start init_record");
  (*mr) = (MOD_RECORD *)malloc(sizeof(MOD_RECORD));

  if (!(*mr))
    goto mr_err;

  (*mr)->source_mac = (unsigned char *)malloc(len);

  if (!((*mr)->source_mac))
    goto mac_err;

  TAILQ_INIT(&((*mr)->global_macs_head));

  // TODO: How to check whether the malloc works well?

  APP_LOG("Modification Record Init Success!");
  return SUCCESS;
mac_err:
  free((*mr)->source_mac);
mr_err:
  free((*mr));
  return FAILURE;
}

/**
 * @brief Destruct the modification record
 * @param mr Data structure of the modification record
 * @return SUCCESS(1)/FAILURE(0)
 */
int free_record(MOD_RECORD *mr)
{
  APP_LOG("Free the Modification Record");
  free(mr->source_mac);

  MR_ENTRY *tmp;
  TAILQ_FOREACH(tmp, &(mr->global_macs_head), entries)
  {
    TAILQ_REMOVE(&(mr->global_macs_head), tmp, entries);
    free_entry(tmp);
  }

  TAILQ_INIT(&(mr->global_macs_head));
  free(mr);
  APP_LOG("Free Success");
  return SUCCESS;
}

/**
 * @brief Initialize the entry in the modification record
 * @param entry Entry to be initialized
 * @param len Length of MAC
 */
int init_entry(MR_ENTRY **entry, int len)
{
  (*entry) = (MR_ENTRY *)malloc(sizeof(MR_ENTRY));

  if (!(*entry))
    goto entry_err;

  (*entry)->writer = (unsigned char *)malloc(len);

  if (!((*entry)->writer))
    goto id_err;

  (*entry)->prior_msg_hash = (unsigned char *)malloc(len);

  if (!((*entry)->prior_msg_hash))
    goto hash_err;

  (*entry)->modification_hash = (unsigned char *)malloc(len);

  if (!((*entry)->modification_hash))
    goto err;

  return SUCCESS;
err:
  free((*entry)->prior_msg_hash);
hash_err:
  free((*entry)->writer);
id_err:
  free((*entry));
entry_err:
  return FAILURE;
}

/**
 * @brief Free the entry
 * @param entry Entry to be freed
 * @return SUCCESS(0)/FAILURE(-1)
 */
int free_entry(MR_ENTRY *entry)
{
  free(entry->writer);
  free(entry->prior_msg_hash);
  free(entry->modification_hash);
  free(entry);

  return SUCCESS;
}

/**
 * @brief Add the source's MAC
 * @param sp Security Parameters
 * @param mr Modification Record
 * @param msg Source Message
 * @param mlen Length of the source message
 * @param key Secret value
 * @param klen Length of the key
 * @return SUCCESS(0)/FAILURE(-1)
 */
int add_source_mac(SECURITY_PARAMS *sp, MOD_RECORD *mr, unsigned char *msg, int mlen, unsigned char *key, int klen)
{
  APP_LOG2s("Add data source MAC with the message", msg, mlen);
  APP_LOG2s("Key for source MAC", key, klen);
  int rlen;
  unsigned char *tmp;
  tmp = hash(sp, msg, mlen);

  if (!tmp)
    APP_LOG("No tmp");
  else
    APP_LOG("Yes tmp");

  APP_LOG2s("Hash", tmp, sp->mac_length);
  
  hmac_hash(sp, key, klen, msg, mlen, mr->source_mac, &rlen);

  if (rlen < sp->mac_length)
    goto err;

  APP_LOG2s("Source MAC", mr->source_mac, sp->mac_length);

  return SUCCESS;
err:
  return FAILURE;
}

/**
 * @brief Add the global MAC
 * @param sp Security Parameters
 * @param mr Modification Record
 * @param id ID of the writer
 * @param idlen Length of ID
 * @param key MAC key
 * @param klen Length of Key
 * @param prev Hash of Previous Message
 * @param plen Hash Length
 * @param next Next Message
 * @param nlen Length of Next Message
 * @return SUCCESS(0)/FAILURE(-1)
 */
int add_global_mac(SECURITY_PARAMS *sp, MOD_RECORD *mr, unsigned char *id, int idlen, unsigned char *key, int klen, unsigned char *prev, int plen, unsigned char *next, int nlen)
{
  APP_LOG("Add the global mac to the modification record");

  MR_ENTRY *tmp;
  unsigned char *mod;
  int rlen;

  if (init_entry(&tmp, sp->mac_length) < 0)
    goto entry_err;

  memcpy(tmp->writer, id, idlen);
  memcpy(tmp->prior_msg_hash, prev, plen);
  mod = (unsigned char *)malloc(plen + nlen);

  if (!mod)
    goto mod_err;

  memcpy(mod, prev, plen);
  memcpy(mod + plen, next, nlen);
  hmac_hash(sp, key, klen, mod, plen + nlen, tmp->modification_hash, &rlen);

  if (rlen < sp->mac_length)
    goto err;

  TAILQ_INSERT_TAIL(&(mr->global_macs_head), tmp, entries);

  free(mod);

  APP_LOG("----- Add Global MAC -----");
  APP_LOG2s("ID", tmp->writer, sp->mac_length);
  APP_LOG2s("Prev", tmp->prior_msg_hash, sp->mac_length);
  APP_LOG2s("Mod", tmp->modification_hash, sp->mac_length);
  printf("\n");

  return SUCCESS;
err:
  free(mod);
mod_err:
  free_entry(tmp);
entry_err:
  return FAILURE;
}

/**
 * @brief Print the modification record
 */
int print_record(MOD_RECORD *mr)
{
  
}

int verify_record()
{
  return SUCCESS;
}
