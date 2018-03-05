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
#include <openssl/hmac.h>
#include <sys/time.h>

#define DEFAULT_MAC_LENGTH  16
#define DEFAULT_KEY_LENGTH  32

typedef struct security_parameters
{
  const EVP_MD *hash_function;
  int key_length;
  int mac_length;
} SECURITY_PARAMS;

int a(int, unsigned char *);
unsigned char *p_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *seed, int slen, int idx, unsigned char *result, int *rlen);
int prf(unsigned char *, unsigned char *, unsigned char *, unsigned char *);
unsigned char *hmac_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *msg, int mlen, unsigned char *result, int *rlen);

#endif /* __PRF_H__ */
