#ifndef OPENSSL_HEADER_SSL_MB_H
#define OPENSSL_HEADER_SSL_MB_H

#include <openssl/stack.h>
#include <openssl/digest.h>
#include <openssl/sha.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

#define MB_MIDDLEBOX_TYPE_DUMMY 0
#define MB_MIDDLEBOX_TYPE_CLIENT 1
#define MB_MIDDLEBOX_TYPE_SERVER 2
#define MB_MIDDLEBOX_TYPE_CLIENT_WITH_SCT 3
#define MB_MIDDLEBOX_TYPE_SERVER_WITH_SCT 4

#define CLIENT_MAX_MB_KEY_SIZE 65
#define MODIFICATION_RECORD_HASH_SIZE 32
#define EXTENDED_FINISHED_HASH_SIZE 32
#define EXTENDED_FINISHED_MAX_BEFORE_HASH_SIZE (EVP_MAX_MD_SIZE + 4 + EVP_MAX_MD_SIZE + EXTENDED_FINISHED_HASH_SIZE) 

#define SWAP16(s) (((((s)) << 8) | (((s) >> 8))))

// #define DEBUG
#ifdef DEBUG
#define PRINTK(msg, arg1, arg2) \
 printf("[matls] %s: %s (%d bytes) ", __func__, msg, arg2); \
 for (int pk_idx=0;pk_idx<arg2;pk_idx++) \
 { \
 if (pk_idx % 10 == 0) \
     printf("\n"); \
   printf("%02X ", arg1[pk_idx]); \
 } \
 printf("\n");
#else
#define PRINTK(msg, arg1, arg2) ;
#endif /* DEBUG */

typedef struct mb_mac_table_entry_st {
  uint8_t data[EVP_MAX_MD_SIZE];
  uint16_t len;
} MAC_TABLE_ENTRY;

typedef struct mb_id_table_entry_st {
  uint8_t data[SHA256_DIGEST_LENGTH];
} ID_TABLE_ENTRY;

#endif
