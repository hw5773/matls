/**
 * @file sp.h
 * @author Hyunwoo Lee
 * @date 23 Mar 2018
 * @brief This file is to define the constants and the security parameters
 */

#ifndef __SP_H__
#define __SP_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <sys/time.h>

enum prf_algorithm { tls_prf_sha256 };
enum bulk_cipher_algorithm { rc4, three_des, aes };
enum cipher_type { stream, block, aead };
enum mac_algorithm { hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512 };
enum compression_method { null };


/**
 * @brief Data structure for security parameters
 */

typedef struct security_parameters
{
  int middlebox;  /**< 1 for middlebox */
  enum prf_algorithm prf_algorithm;
  enum bulk_cipher_algorithm bulk_cipher_algorithm;
  enum cipher_type cipher_type;
  uint8_t enc_key_length;
  uint8_t block_length;
  uint8_t fixed_iv_length;
  uint8_t record_iv_length;
  enum mac_algorithm mac_algorithm;
  uint8_t mac_length;
  uint8_t mac_key_length;
  enum compression_method compression_method;
  unsigned char master_secret[SSL3_MASTER_SECRET_SIZE];
  unsigned char client_random[SSL3_RANDOM_SIZE];
  unsigned char server_random[SSL3_RANDOM_SIZE];
} SECURITY_PARAMS;

/**
 * @brief Data structure for key blocks
 */

typedef struct key_blocks
{
  unsigned char *client_write_MAC_key;
  unsigned char *server_write_MAC_key;
  unsigned char *client_write_key;
  unsigned char *server_write_key;
  unsigned char *client_write_IV;
  unsigned char *server_write_IV;
} KEY_BLOCKS;

#elif
#endif /* __SP_H__ */
