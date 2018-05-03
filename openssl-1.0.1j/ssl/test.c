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
#include <openssl/objects.h>
#include "ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#define SECP256r1_PUBKEY_LENGTH    64;

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx) {
    BIGNUM *n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    (*pair) = (struct keypair *)malloc(sizeof(struct keypair));
    (*pair)->pri = BN_new();
    (*pair)->pub = EC_POINT_new(group);

    BN_rand_range((*pair)->pri, n); //private key
    EC_POINT_mul(group, (*pair)->pub, (*pair)->pri, NULL, NULL, ctx); //public key

    return 1;
}

int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx)
{
    int klen = key_length / 2;
    unsigned char *xstr = (unsigned char *)malloc(klen); //klen+1?
    unsigned char *ystr = (unsigned char *)malloc(klen); //klen+1?

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    memcpy(xstr, input, klen);
    memcpy(ystr, input + klen, klen);

    BN_hex2bn(&x, xstr);
    BN_hex2bn(&y, ystr);

    EC_POINT_set_affine_coordinates_GFp(group, pubkey, x, y, ctx);

    free(xstr);
    free(ystr);

    BN_free(x);
    BN_free(y);

    return 1;
}

int pub_to_char(EC_POINT *input, unsigned char *serv_str, int serv_length, EC_GROUP *group, BN_CTX *ctx)
{
	*serv_length = 2*sizeof(int);

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	EC_POINT_get_affine_coordinates_GFp(group, input, x, y, ctx);

	unsigned char *xstr = BN_bn2hex(x);
	unsigned char *ystr = BN_bn2hex(y);

	BN_free(x);
	BN_free(y);

	memcpy(serv_str, xstr, sizeof(xstr));
	memcpy(serv_str + sizeof(xstr), ystr, sizeof(ystr));

	OPENSSL_free(xstr);
	OPENSSL_free(ystr);
	
	return 1;
}


int handle_parse_errors() {
    SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
    *al = SSL_AD_ILLEGAL_PARAMETER;
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

    unsigned int mb_len;
    unsigned char *p;
    unsigned int i;

    printf("PROGRESS: Read the mb length from the extension packet\n");
    /* Parse the length byte */
    if(len < 1)
    {
        return handle_parse_errors();
    }

    p = d;

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    n2s(p,s->mb_info.group_id);

    if(s->mb_info.group_id != NID_X9_62_prime256v1) //SSL_CURVE_SECP256R1
    {
        return handle_parse_errors();
    }

    /* Check num_keys */
    s->mb_info.num_keys = *(p++);

    if(s->mb_info.num_keys < 1)
    {
        return handle_parse_errors();
    }

    /* Generate server keypair */
    struct keypair *serv_keypair;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();

    make_keypair(serv_keypair, group, ctx);
    s->mb_info->serv_keypair = serv_keypair;

    /* Generate MAC keys */
    EC_POINT *serv_result = EC_POINT_new(group);

    int n, serv_length;
    EC_POINT *peer_pub;
    unsigned char *peer_str, *serv_str;

    for(i=0; i<s->mb_info.num_keys; i++)
    {
        s->mb_info.key_length[i] = *(p++);
        peer_str = (unsigned char *)malloc(s->mb_info.key_length[i]);
        memcpy(peer_str, p, s->mb_info.key_length[i]);
        p += s->mb_info.key_length[i];

        peer_pub = EC_POINT_new(group);
        char_to_pub(peer_str, s->mb_info.key_length[i], peer_pub, group, ctx);
        EC_POINT_mul(group, serv_result, NULL, peer_pub, serv_keypair->pri, ctx);
        pub_to_char(serv_result, serv_str, &serv_length, group, ctx);

        tls1_PRF(ssl_get_algorithm2(s),
                TLS_MD_GLOBAL_MAC_KEY_CONST, TLS_MD_GLOBAL_MAC_KEY_CONST_SIZE,
                s->s3->server_random, SSL3_RANDOM_SIZE,
                s->s3->client_random, SSL3_RANDOM_SIZE,
                NULL, 0, NULL, 0,
                serv_str, serv_length,
                s->mb_info.mac_array[i], NULL, SSL_MAX_GLOBAL_MAC_KEY_LENGTH); //LENGTH: 48
        
        free(peer_str);
        EC_POINT_free(peer_pub);
    }

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

	uint16_t group_id = s->mb_info.group_id;
	uint8_t num_keys = 1;
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	BN_CTX *ctx = BN_CTX_new();
	unsigned char *serv_str;
	int serv_length;

    if (p) {
		s2n(group_id, p);
		(p++) = num_keys;
		pub_to_char(s->mb_info.serv_keypair.pub, serv_str, &serv_length, group, ctx);
		(p++) = serv_length; //pubkey_len
		memcpy(p, serv_str, serv_length); //pubkey
	}

    printf("PROGRESS: Set the length for the extension\n");
    *len = 4 + serv_length; 
    printf("PROGRESS: Complete Setting the length for the extension: %d\n", *len);

    return 1;
}

/*
 * Parse the server's mb and abort if it's not right
 */
int ssl_parse_serverhello_mb_ext(SSL *s, unsigned char *p, int size, int *al)
{
    return 1;
}
