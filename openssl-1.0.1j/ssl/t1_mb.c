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
    BIGNUM *n = BN_new();
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
    int ret;
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
    printf("x ret: %d\n", ret);
	ret = BN_bn2bin(y, ystr);
    printf("y ret: %d\n", ret);

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
    printf("adding clienthello mb\n");
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
    struct keypair *serv_keypair;
    EC_GROUP *group;
    BIGNUM *x, *y;
    EC_POINT *secret, *peer_pub;
    BN_CTX *ctx;

    printf("PROGRESS: Read the mb length from the extension packet\n");
    /* Parse the length byte */
    if(len < 1)
    {
        return handle_parse_errors();
    }

    printf("PROGRESS: Length: %d\n", len);
    p = d;
    p += 2;

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    n2s(p,s->mb_info.group_id);

    printf("PROGRESS: Group ID: %d\n", s->mb_info.group_id);

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
    s->mb_info.key_length = (int *)calloc(nk, sizeof(int));
    s->mb_info.secret = (unsigned char **)calloc(nk, sizeof(unsigned char *));
    s->mb_info.mac_array = (unsigned char **)calloc(nk, sizeof(unsigned char *));

    for (i=0; i<nk; i++)
    {
      s->mb_info.mac_array[i] = (unsigned char *)malloc(SSL_MAX_GLOBAL_MAC_KEY_LENGTH);
    }
    printf("PROGRESS: Number of Keys: %d\n", nk);
    if(nk < 1)
    {
        return handle_parse_errors();
    }

    ctx = BN_CTX_new();
    x = BN_new();
    y = BN_new();

    make_keypair(&serv_keypair, group, ctx);
    s->mb_info.serv_keypair = serv_keypair;

    for(i=0; i<nk; i++)
    {
        secret = EC_POINT_new(group);
        n2s(p, klen);
        s->mb_info.key_length[i] = klen;
        printf("key length[%d]: %d\n", i, klen);
        peer_str = (unsigned char *)malloc(klen);
        memcpy(peer_str, p, klen);
        p += klen;

        peer_pub = EC_POINT_new(group);
        char_to_pub(peer_str, klen, peer_pub, group, ctx);
        EC_POINT_mul(group, secret, NULL, peer_pub, serv_keypair->pri, ctx);
        EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
        secret_str = (unsigned char *)malloc((klen-1)/2);
        BN_bn2bin(x, secret_str);
        s->mb_info.secret[i] = secret_str;

        free(peer_str);
        EC_POINT_free(secret);
        EC_POINT_free(peer_pub);
    }

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    s->mb_enabled = 1; // Enable the mb mode

    printf("PROGRESS: MB Extension is enabled\n");

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
	unsigned char *serv_str;
	int i, j, serv_length, plen;

    switch(group_id)
    {
    case SSL_CURVE_SECP256R1:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      plen = serv_length = 2 * 256 / 8 + 1;
    default:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      plen = serv_length = 2 * 256 / 8 + 1;
    }

    ctx = BN_CTX_new();

    if (p) {
		s2n(group_id, p);
		*(p++) = num_keys;
		pub_to_char(s->mb_info.serv_keypair->pub, &serv_str, &serv_length, group, ctx);
		s2n(serv_length, p); //pubkey_len
		memcpy(p, serv_str, serv_length); //pubkey
        p += serv_length;
	
        PRINTK("Server Pubkey", serv_str, serv_length);
        unsigned char *tmp = (unsigned char *)malloc(32);

        for (i=0; i<s->mb_info.num_keys; i++)
        {
          printf("before t1_prf\n");
          memcpy(tmp, s->mb_info.secret[i] + 1, 32);

          t1_prf(TLS_MD_GLOBAL_MAC_KEY_CONST, TLS_MD_GLOBAL_MAC_KEY_CONST_SIZE,
                s->s3->server_random, SSL3_RANDOM_SIZE,
                s->s3->client_random, SSL3_RANDOM_SIZE,
                NULL, 0, NULL, 0,
                s->mb_info.secret[i], SECRET_LENGTH,
                s->mb_info.mac_array[i], SSL_MAX_GLOBAL_MAC_KEY_LENGTH); //LENGTH: 48

          printf("after t1_prf\n");
          PRINTK("Server Random", s->s3->server_random, SSL3_RANDOM_SIZE);
          PRINTK("Client Random", s->s3->client_random, SSL3_RANDOM_SIZE);
          PRINTK("Secret", tmp, 32);
          PRINTK("Global MAC", s->mb_info.mac_array[i], SSL_MAX_GLOBAL_MAC_KEY_LENGTH);
        }
    }

    printf("PROGRESS: Set the length for the extension\n");
    *len = 5 + serv_length; 
    printf("PROGRESS: Complete Setting the length for the extension: %d\n", *len);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 1;
}

/*
 * Parse the server's mb and abort if it's not right
 */
int ssl_parse_serverhello_mb_ext(SSL *s, unsigned char *p, int size, int *al)
{
    return 1;
}
