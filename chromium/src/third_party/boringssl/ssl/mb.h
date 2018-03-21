#ifndef OPENSSL_HEADER_SSL_MB_H
#define OPENSSL_HEADER_SSL_MB_H

#include <openssl/stack.h>
#include <openssl/digest.h>
#include <openssl/sha.h>

typedef struct mb_mac_table_entry_st {
  uint8_t data[EVP_MAX_MD_SIZE];
  uint16_t len;
} MAC_TABLE_ENTRY;

typedef struct mb_id_table_entry_st {
  uint8_t data[SHA256_DIGEST_LENGTH];
} ID_TABLE_ENTRY;

#endif
