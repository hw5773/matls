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
    return FAILURE;

  (*mr)->endpoint_mac = (unsigned char *)malloc(len);

  if (!((*mr)->endpoint_mac))
    return FAILURE;

  TAILQ_INIT(&((*mr)->global_macs_head));

  APP_LOG("Modification Record Init Success!");
  return SUCCESS;
}

/**
 * @brief Destruct the modification record
 * @param mr Data structure of the modification record
 * @return SUCCESS(1)/FAILURE(0)
 */
int free_record(MOD_RECORD *mr)
{
  APP_LOG("Free the Modification Record");
  free(mr->endpoint_mac);
  TAILQ_INIT(&(mr->global_macs_head));
  free(mr);
  APP_LOG("Free Success");
  return SUCCESS;
}

/**
 * @brief Add the endpoint's MAC
 * @param sp Security Parameters
 * @param mr Modification Record
 * @param msg Source Message
 * @param mlen Length of the source message
 * @param key Secret value
 * @param klen Length of the key
 * @return SUCCESS(1)/FAILURE(0)
 */
int add_source_mac(SECURITY_PARAMS *sp, MOD_RECORD *mr, unsigned char *msg, int mlen, unsigned char *key, int klen)
{
  APP_LOG1s("Add endpoint MAC with the message", msg);
  return SUCCESS;
}

int add_record(unsigned char *record, int rec_len, unsigned char *id, int id_len, unsigned char *mac_key, int mk_len, unsigned char *prev, int prev_len, unsigned char *next, int next_len)
{
  return SUCCESS;
}

int verify_record()
{
  return SUCCESS;
}
