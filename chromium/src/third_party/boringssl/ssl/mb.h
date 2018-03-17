#ifndef OPENSSL_HEADER_SSL_MB_H
#define OPENSSL_HEADER_SSL_MB_H

#include <openssl/stack.h>
#include <openssl/digest.h>

typedef struct mb_mac_table_entry {
  uint8_t data[EVP_MAX_MD_SIZE];
  uint16_t len;
} MAC_TABLE_ENTRY;

#endif
