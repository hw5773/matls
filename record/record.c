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

  TAILQ_INIT(&((*mr)->global_macs_head));

  // TODO: How to check whether the malloc works well?

  (*mr)->num_of_global_macs = 0;

  APP_LOG("Modification Record Init Success!");
  return SUCCESS;
mr_err:
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

  if (mr->source_mac)
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

  mr->source_mac = (unsigned char *)malloc(sp->mac_length);

  if (!(mr->source_mac))
    goto err;

  hmac_hash(sp, key, klen, hash(sp, msg, mlen), sp->mac_length, mr->source_mac, &rlen);

  APP_LOG2s("Source Hash", hash(sp, msg, mlen), sp->mac_length);
  APP_LOG2s("Source MAC", mr->source_mac, sp->mac_length);

  if (rlen < sp->mac_length)
    goto mac_err;

  return SUCCESS;
mac_err:
  free(mr->source_mac);
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
  unsigned char *mod, *n;
  int rlen;

  if (init_entry(&tmp, sp->mac_length) < 0)
    goto entry_err;

  memcpy(tmp->writer, id, idlen);
  memcpy(tmp->prior_msg_hash, prev, plen);
  n = hash(sp, next, nlen);
  mod = (unsigned char *)malloc(2 * sp->mac_length);

  if (!mod)
    goto mod_err;

  memcpy(mod, prev, plen);
  memcpy(mod + plen, n, sp->mac_length);
  hmac_hash(sp, key, klen, mod, plen + sp->mac_length, tmp->modification_hash, &rlen);

  if (rlen < sp->mac_length)
    goto err;

  free(mod);

  TAILQ_INSERT_HEAD(&(mr->global_macs_head), tmp, entries);
  mr->num_of_global_macs += 1;

  APP_LOG("----- Add Global MAC -----");
  APP_LOG2s("ID", tmp->writer, sp->mac_length);
  APP_LOG2s("Secret", key, sp->key_length);
  APP_LOG2s("Prev", tmp->prior_msg_hash, sp->mac_length);
  APP_LOG2s("Next", n, sp->mac_length);
  APP_LOG2s("Mod", tmp->modification_hash, sp->mac_length);

  return SUCCESS;
err:
  free(mod);
mod_err:
  free_entry(tmp);
entry_err:
  return FAILURE;
}

/**
 * @brief Serialize the data structure for the modification record
 * @param sp Security parameters
 * @param mr Data structure for modification record
 * @detail | length (2 bytes) | modification record (length bytes) |
 */
unsigned char *serialize_record(SECURITY_PARAMS *sp, MOD_RECORD *mr, int *len)
{
  unsigned char *ret, *p;
  MR_ENTRY *tmp;

  (*len) = (3 * mr->num_of_global_macs + 1) * sp->mac_length;

  APP_LOG1d("Length", (*len));

  ret = (unsigned char *)malloc((*len) + 2);
  p = ret;
  s2n((*len), p);

  memcpy(p, mr->source_mac, sp->mac_length);
  p += sp->mac_length;

  TAILQ_FOREACH(tmp, &(mr->global_macs_head), entries)
  {
    memcpy(p, tmp->writer, sp->mac_length);
    p += sp->mac_length;
    memcpy(p, tmp->prior_msg_hash, sp->mac_length);
    p += sp->mac_length;
    memcpy(p, tmp->modification_hash, sp->mac_length);
    p += sp->mac_length;
  }

  return ret;
}

/**
 * @brief Deserialize the string into the data structure
 * @param sp Security parameters
 * @param str String to be constructed into the data structure
 * @param len Length of the string
 */
MOD_RECORD *deserialize_record(SECURITY_PARAMS *sp, unsigned char *str, int len)
{
  MOD_RECORD *mr;
  unsigned char *p = str;
  int i, l;

  n2s(p, l);

  APP_LOG1d("Length", l);

  // Length information is wrong
  if (l != (len - 2))
    goto err;

  if (init_record(&mr, sp->mac_length) < 0)
    goto err;

  mr->source_mac = (unsigned char *)malloc(sp->mac_length);

  if (!(mr->source_mac))
    goto mr_err;

  memcpy(mr->source_mac, p, sp->mac_length);
  p += sp->mac_length;
  l -= sp->mac_length;

  mr->num_of_global_macs = (len - sp->mac_length) / 3;

  APP_LOG1d("Num of Global MACs", mr->num_of_global_macs);

  for (i=0; i<l; i+=(3 * sp->mac_length))
  {
    MR_ENTRY *tmp;
    if (init_entry(&tmp, sp->mac_length) < 0)
      goto entry_err;
    memcpy(tmp->writer, p, sp->mac_length);
    p += sp->mac_length;
    memcpy(tmp->prior_msg_hash, p, sp->mac_length);
    p += sp->mac_length;
    memcpy(tmp->modification_hash, p, sp->mac_length);
    p += sp->mac_length;
    TAILQ_INSERT_TAIL(&(mr->global_macs_head), tmp, entries);
  }

  return mr;

entry_err:
mr_err:
  free_record(mr);
err:
  return NULL;
}

int find_id(SECURITY_PARAMS *sp, unsigned char *x, unsigned char id[][sp->mac_length], int num_of_ids)
{
  int i, ret = -1;

  for (i=0; i<=num_of_ids; i++)
  {
    if (strncmp(id[i], x, sp->mac_length) == 0)
    {
      ret = i;
      break;
    }
  }

  return ret;
}

/**
 * @brief Verify the modification record
 * @param sp Security parameters
 * @param mr Modification record
 * @param msg Received final message
 * @param id ID table
 * @param secret Global MAC keys
 * @return SUCCESS(0)/FAILURE(-1)
 */
int verify_record(SECURITY_PARAMS *sp, MOD_RECORD *mr, unsigned char *h, unsigned char id[][sp->mac_length], unsigned char secret[][sp->key_length], int num_of_ids)
{
  MR_ENTRY *tmp;
  unsigned char *key, *mod, *gmac, *prev, *curr = h;
  int index, len;

  mod = (unsigned char *)malloc(2 * sp->mac_length);

  if (!mod)
    goto err;

  TAILQ_FOREACH(tmp, &(mr->global_macs_head), entries)
  {
    index = find_id(sp, tmp->writer, id, num_of_ids);
    APP_LOG1d("index", index);
    key = secret[index];
    prev = tmp->prior_msg_hash;
    memcpy(mod, prev, sp->mac_length);
    memcpy(mod + sp->mac_length, curr, sp->mac_length);
    gmac = hmac_hash(sp, key, sp->key_length, mod, 2 * sp->mac_length, NULL, &len);

    if (len != sp->mac_length)
      goto len_err;

    APP_LOG2s("Secret", secret[index], sp->key_length);
    APP_LOG2s("Prev", prev, sp->mac_length);
    APP_LOG2s("Next", curr, sp->mac_length);
    APP_LOG2s("Generated", gmac, sp->mac_length);

    if (strncmp(gmac, tmp->modification_hash, sp->mac_length) == 0)
    {
      APP_LOG1d("Verified", index);
    } 
    else
    {
      APP_LOG1d("Failed", index);
      goto verification_err;
    }
    memcpy(curr, prev, sp->mac_length);
  }

  APP_LOG("Verify Source MAC");
  gmac = hmac_hash(sp, secret[0], sp->key_length, curr, sp->mac_length, NULL, &len);
  if (len != sp->mac_length)
    goto len_err;

  APP_LOG2s("Source MAC Key", secret[0], sp->key_length);
  APP_LOG2s("Source Hash", curr, sp->mac_length);
  APP_LOG2s("Source MAC", mr->source_mac, sp->mac_length);
  APP_LOG2s("Generated MAC", gmac, sp->mac_length);

  if (strncmp(gmac, mr->source_mac, sp->mac_length) == 0)
    APP_LOG("Source Verified");
  else
  {
    APP_LOG("Source Verification Failed");
    goto verification_err;
  }

  return SUCCESS;

verification_err:
len_err:
  free(mod);
err:
  return FAILURE;
}

/**
 * @brief Print the modification record
 * @param sp Security parameters
 * @param mr Modification record
 */
int print_record(SECURITY_PARAMS *sp, MOD_RECORD *mr)
{
  struct entry *tmp;

  APP_LOG("Print Record");
  APP_LOG("----- Source MAC -----");
  APP_LOG2s("  MAC", mr->source_mac, sp->mac_length);

  TAILQ_FOREACH(tmp, &(mr->global_macs_head), entries)
  {
    APP_LOG("----- Global MAC -----");
    APP_LOG2s("  ID", tmp->writer, sp->mac_length);
    APP_LOG2s("  Prev", tmp->prior_msg_hash, sp->mac_length);
    APP_LOG2s("  Mod", tmp->modification_hash, sp->mac_length);
    APP_LOG("----------------------");
  }
}
