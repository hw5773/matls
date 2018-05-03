
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>

#include "ssl_locl.h"
#include "tls1.h"
#include "logs.h"
#include "matls.h"

#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#define SSL_CURVE_SECP256R1 23
#define SECP256r1_PUBKEY_LENGTH    64;
#define SECRET_LENGTH 32

int idx;
int lock;

#define PRINTK(msg, arg1, arg2) \
  printf("[matls] %s: %s (%d bytes) ", __func__, msg, arg2); \
  for (idx=0;idx<arg2;idx++) \
  { \
    if (idx % 10 == 0) \
      printf("\n"); \
    printf("%02X ", arg1[idx]); \
  } \
  printf("\n");

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx) {
  MA_LOG("make keypair");
  BIGNUM *n = BN_new();
  MA_LOG("bn_new()");
  EC_GROUP_get_order(group, n, ctx);

  (*pair) = (struct keypair *)malloc(sizeof(struct keypair));
  (*pair)->pri = BN_new();
  (*pair)->pub = EC_POINT_new(group);

  BN_rand_range((*pair)->pri, n); //private key
  EC_POINT_mul(group, (*pair)->pub, (*pair)->pri, NULL, NULL, ctx); //public key
  BIGNUM *x, *y;
  x = BN_new();
  y = BN_new();
  EC_POINT_get_affine_coordinates_GFp(group, (*pair)->pub, x, y, ctx);

  return 1;
}

int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx)
{
    int klen = (key_length - 1)/ 2;
    unsigned char *xstr = (unsigned char *)malloc(klen); //klen+1?
    unsigned char *ystr = (unsigned char *)malloc(klen); //klen+1?

    BIGNUM *x, *y;
    
    memcpy(xstr, input + 1, klen);
    memcpy(ystr, input + klen + 1, klen);

    x = BN_new();
    y = BN_new();

    BN_bin2bn(xstr, klen, x);
    BN_bin2bn(ystr, klen, y);

    EC_POINT_set_affine_coordinates_GFp(group, pubkey, x, y, ctx);

    free(xstr);
    free(ystr);

    BN_free(x);
    BN_free(y);

    return 1;
}

int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, EC_GROUP *group, BN_CTX *ctx)
{
  int key_bytes, ret;
  unsigned char *xstr, *ystr;

  if (EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1)
    key_bytes = 256 / 8;
  else
    return -1;

	*slen = 2 * key_bytes + 1;
    (*secret_str) = (unsigned char *)malloc(*slen);

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);

  xstr = (unsigned char *)malloc(key_bytes);
  ystr = (unsigned char *)malloc(key_bytes);
	ret = BN_bn2bin(x, xstr);
	ret = BN_bn2bin(y, ystr);

	BN_free(x);
	BN_free(y);

  memset((*secret_str), 0x04, 1);
	memcpy((*secret_str) + 1, xstr, key_bytes);
	memcpy((*secret_str) + key_bytes + 1, ystr, key_bytes);

	OPENSSL_free(xstr);
	OPENSSL_free(ystr);
	
	return 1;
}


int handle_parse_errors() {
    //SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
    //*al = SSL_AD_ILLEGAL_PARAMETER;
    printf("Error\n");
    return 0;
}

/* Add the client's mb */
int ssl_add_clienthello_mb_ext(SSL *s, unsigned char *p, int *len,
        int maxlen)
{
    MA_LOG("adding clienthello mb");

    int group_id;
    int num_keys;
    EC_GROUP *group;
    BN_CTX *ctx;
    unsigned char *pub_str;
    int pub_length, plen;
    int ext_len;
    struct keypair *keypair;

    MA_LOG("before if");

    if (p)
    {
      MA_LOG("Before waiting the message");
      while (!(s->pair && s->pair->extension_from_clnt_msg)) {}
      MA_LOG("The client side pair has the extension message");
      memcpy(&(s->mb_info), &(s->pair->mb_info), sizeof(struct mb_st));
      group_id = s->mb_info.group_id;
      MA_LOG1d("group_id is set to", group_id);
      ctx = BN_CTX_new();

      switch(group_id)
      {
      case SSL_CURVE_SECP256R1:
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        plen = pub_length = 2 * 256 / 8 + 1;
      default:
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        plen = pub_length = 2 * 256 / 8 + 1;
      }

      MA_LOG1d("before memcpy", s->pair->extension_from_clnt_msg_len);
      memcpy(p, s->pair->extension_from_clnt_msg, s->pair->extension_from_clnt_msg_len);
      free(s->pair->extension_from_clnt_msg);

      MA_LOG("after free");

      if (!(s->mb_info.keypair))
      {
        MA_LOG("before make key pair");
        if (!(s->pair && s->pair->mb_info.in_func))
        {
          s->mb_info.in_func = 1;
          make_keypair(&keypair, group, ctx);
          s->mb_info.keypair = keypair;
          //memcpy(s->mb_info.keypair, keypair, sizeof(struct keypair));
          MA_LOG("1");
          s->mb_info.exist = 1;
          if (s->pair)
          {
            if (!(s->pair->mb_info.keypair))
            {
              s->pair->mb_info.keypair = (struct keypair *)malloc(sizeof(struct keypair));
              memcpy(s->pair->mb_info.keypair, keypair, sizeof(struct keypair));
            }
          MA_LOG("3");
          }

          s->mb_info.in_func = 0;
        }
        else
        {
          while(!(s->pair->mb_info.exist)) {}
        }
        MA_LOG("2");

      }

      MA_LOG("before pub to char");
      while (!(s->mb_info.exist)) {}
      MA_LOG1p("keypair->pub", s->mb_info.keypair->pub);
      pub_to_char(s->mb_info.keypair->pub, &pub_str, &pub_length, group, ctx);
      MA_LOG1d("the length of public key", pub_length);

      n2s(p, ext_len);
      p -= 2;
      MA_LOG1d("ext_len before", ext_len);
      ext_len = ext_len + 2 + pub_length;
      MA_LOG1d("ext_len after", ext_len);
      s2n(ext_len, p);
      p += 2;
      num_keys = *p;
      MA_LOG1d("before number of keys: %d\n", (int)*p);
      *p = num_keys + 1;
      MA_LOG1d("after number of keys: %d\n", (int)*p);
      p += s->pair->extension_from_clnt_msg_len - 4;
      s2n(pub_length, p);
      memcpy(p, pub_str, pub_length);

      MA_LOG1d("s->pair->extension_from_clnt_msg_len", s->pair->extension_from_clnt_msg_len);
      *len = s->pair->extension_from_clnt_msg_len + 2 + pub_length;
      MA_LOG1d("length of client hello extension", *len);
    }

    MA_LOG("after if");

    return 1;
}

/*
 * Parse the client's mb and abort if it's not right
 */
// This is the function for parsing the ClientHello message from the client
// The purpose is to check the intention of the client
// Input: SSL object, Extension Packet, Alert
// Output: 1 for Success, 0 for Failure
int ssl_parse_clienthello_mb_ext(SSL *s, unsigned char *d, int len, int *al)
{
    // SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT

    unsigned char *p;
    int i, slen, klen, nk, plen;  // klen: key length, nk: number of keys, plen: EC point length
    unsigned char *secret_str, *peer_str;
    struct keypair *keypair;
    EC_GROUP *group;
    BIGNUM *x, *y;
    EC_POINT *secret, *peer_pub;
    BN_CTX *ctx;

    MA_LOG1d("Read the mb length from the extension packet", len);
    /* Parse the length byte */
    if(len < 1)
    {
        return handle_parse_errors();
    }

    MA_LOG1d("Length", len);
    MA_LOG("Copy this extension message to my SSL struct (not to pair)");
    s->extension_from_clnt_msg_len = len;
    s->extension_from_clnt_msg = (unsigned char *)malloc(len);
    MA_LOG1p("after malloc", s->extension_from_clnt_msg);
    memcpy(s->extension_from_clnt_msg, d, len);
    MA_LOG1d("after memcpy", len);
    p = d;
    p += 2;

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    n2s(p,s->mb_info.group_id);

    MA_LOG1d("Group ID", s->mb_info.group_id);

    switch(s->mb_info.group_id)
    {
    case SSL_CURVE_SECP256R1:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      plen = 2 * 256 / 8 + 1;
    default:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      plen = 2 * 256 / 8 + 1;
    }

    /* Check num_keys */
    nk = s->mb_info.num_keys = *(p++);
    MA_LOG1d("Number of Keys (nk)", nk);

    if (s->middlebox) // middlebox, index 0: client->server, index 1: server->client
    {

      nk = 2;
      s->mb_info.key_length = (int *)calloc(2, sizeof(int));
      s->mb_info.secret = (unsigned char **)calloc(2, sizeof(unsigned char *));
      s->mb_info.mac_array = (unsigned char **)calloc(2, sizeof(unsigned char *));
    }
    else
    {
      s->mb_info.key_length = (int *)calloc(nk, sizeof(int));
      s->mb_info.secret = (unsigned char **)calloc(nk, sizeof(unsigned char *));
      s->mb_info.mac_array = (unsigned char **)calloc(nk, sizeof(unsigned char *));
    }

    for (i=0; i<nk; i++)
    {
      s->mb_info.mac_array[i] = (unsigned char *)malloc(SSL_MAX_GLOBAL_MAC_KEY_LENGTH);
    }
    MA_LOG1d("Number of Keys (nk, revised?)", nk);

    if(nk < 1)
    {
        return handle_parse_errors();
    }

    ctx = BN_CTX_new();
    x = BN_new();
    y = BN_new();

    if (!s->mb_info.keypair)
    {
      if (!(s->pair && s->pair->mb_info.in_func))
      {
        s->mb_info.in_func = 1;
        make_keypair(&keypair, group, ctx);
        s->mb_info.keypair = keypair;
        //memcpy(s->mb_info.keypair, keypair, sizeof(struct keypair));
        s->mb_info.exist = 1;

        if (s->pair)
        {
          if (!(s->pair->mb_info.keypair))
          {
            s->pair->mb_info.keypair = (struct keypair *)malloc(sizeof(struct keypair));
            memcpy(s->pair->mb_info.keypair, keypair, sizeof(struct keypair));
          }
        }
        s->mb_info.in_func = 0;
      }
      else
      {
        while (!(s->mb_info.exist)) {}
      }
    }

    MA_LOG1p("s->mb_info.keypair", s->mb_info.keypair);

    secret = EC_POINT_new(group);
    n2s(p, klen);
    s->mb_info.key_length[0] = klen;
    peer_str = (unsigned char *)malloc(klen);
    memcpy(peer_str, p, klen);
    p += klen;

    peer_pub = EC_POINT_new(group);
    char_to_pub(peer_str, klen, peer_pub, group, ctx);
    EC_POINT_mul(group, secret, NULL, peer_pub, keypair->pri, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
    secret_str = (unsigned char *)malloc((klen-1)/2);
    BN_bn2bin(x, secret_str);
    s->mb_info.secret[0] = secret_str;

    free(peer_str);
    EC_POINT_free(secret);
    EC_POINT_free(peer_pub);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    s->mb_enabled = 1; // Enable the mb mode

    MA_LOG("MB Extension is enabled");

    return 1;
}

/* Add the server's mb */
// Add the mb extension in the ServerHello message
// If p is 0, it returns the length of the added message in the len
// Input: SSL object, buffer, length to be stored, maximum length
// Output: 1 for Success, 0 for Failure
int ssl_add_serverhello_mb_ext(SSL *s, unsigned char *p, int *len,
        int maxlen)
{
    // group_id (2 bytes) + num_keys (1 byte) + pubkey_len (1 byte) + pubkey (pubkey_len bytes)

	int group_id = s->mb_info.group_id;
	int num_keys = 1;
	EC_GROUP *group;
	BN_CTX *ctx;
	unsigned char *pub_str;
	int i, j, pub_length, plen;

  switch(group_id)
  {
  case SSL_CURVE_SECP256R1:
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    plen = pub_length = 2 * 256 / 8 + 1;
  default:
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    plen = pub_length = 2 * 256 / 8 + 1;
  }

  ctx = BN_CTX_new();

  if (p) {
		s2n(group_id, p);
		*(p++) = num_keys;
		pub_to_char(s->mb_info.keypair->pub, &pub_str, &pub_length, group, ctx);
		s2n(pub_length, p); //pubkey_len
		memcpy(p, pub_str, pub_length); //pubkey
    p += pub_length;
	
    PRINTK("MB Pubkey", pub_str, pub_length);
    unsigned char *tmp = (unsigned char *)malloc(32);

    for (i=0; i<s->mb_info.num_keys; i++)
    {
      memcpy(tmp, s->mb_info.secret[i] + 1, 32);

      t1_prf(TLS_MD_GLOBAL_MAC_KEY_CONST, TLS_MD_GLOBAL_MAC_KEY_CONST_SIZE,
                s->s3->server_random, SSL3_RANDOM_SIZE,
                s->s3->client_random, SSL3_RANDOM_SIZE,
                NULL, 0, NULL, 0,
                s->mb_info.secret[i], SECRET_LENGTH,
                s->mb_info.mac_array[i], SSL_MAX_GLOBAL_MAC_KEY_LENGTH); //LENGTH: 32

      PRINTK("Server Random", s->s3->server_random, SSL3_RANDOM_SIZE);
      PRINTK("Client Random", s->s3->client_random, SSL3_RANDOM_SIZE);
      PRINTK("Secret", tmp, 32);
      PRINTK("Global MAC", s->mb_info.mac_array[i], SSL_MAX_GLOBAL_MAC_KEY_LENGTH);
    }
  }

  MA_LOG("Set the length for the extension matls");
  *len = 5 + pub_length; 
  MA_LOG1d("Complete Setting the length for the extension", *len);

  EC_GROUP_free(group);
  BN_CTX_free(ctx);

  return 1;
}

/*
 * Parse the server's mb and abort if it's not right
 */
int ssl_parse_serverhello_mb_ext(SSL *s, unsigned char *p, int size, int *al)
{
  MA_LOG1d("Parse serverhello matls", size);
  s->extension_from_srvr_msg_len = size;
  s->extension_from_srvr_msg = (unsigned char *)malloc(size);
  memcpy(s->extension_from_srvr_msg, p, size);
  MA_LOG("after memcpy");

  return 1;
}
