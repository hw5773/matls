/**
 * @file table.h
 * @author Hyunwoo Lee
 * @date 7 Mar 2018
 * @brief This file is to define the manipulation for the global MAC key table
 */

#include <sys/queue.h>
#include "prf.h"

typedef struct global_key_info
{
  unsigned char *id;                    /**< ID of the middlebox */
  int idlen;                            /**< Length of ID */                  
  unsigned char *key;                   /**< Global key of the middlebox */
  int klen;                             /**< Length of the global key */
  int role;                             /**< Role of the middlebox */
  TAILQ_ENTRY(global_key_info) entries; /**< Pointer to the next entry */
} KEY_ENTRY;

int init_key_entry()
