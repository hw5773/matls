/**
 * @file prf.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define the attributes and functions for the
 * pseudorandom function
 */

#ifndef __PRF_H__
#define __PRF_H__

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

#define DEFAULT_MAC_LENGTH  16
#define DEFAULT_KEY_LENGTH  32
#define MASTER_SECRET_LENGTH  48
#define FINISHED_LENGTH 12

/**
 * @brief Data structure for Constants
 */
typedef struct security_parameters
{
  const EVP_MD *mac_algorithm;      /**< The hash function used in prf function */
  int mac_length;                  /**< The output length of the hash function */
  int key_length;                   /**< The length of the mac key */
} SECURITY_PARAMS;

unsigned char *hash(SECURITY_PARAMS *sp, unsigned char *msg, int mlen);
unsigned char *p_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *seed, int slen, unsigned char *result, int rlen);
unsigned char *prf(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *label, int llen, unsigned char *seed, int slen, int *rlen);
unsigned char *hmac_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *msg, int mlen, unsigned char *result, int *rlen);
unsigned char *generate_global_mac(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *msg, int mlen, int *rlen);

#endif /* __PRF_H__ */
