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

#define secret_len  100

int handle_parse_errors() {
    SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return 0;
}

unsigned char *ecdh(unsigned char key_length, unsigned char *key_ptr)
{
    EVP_PKEY_CTX *pctx, *kctx; //parameters_context, key_generation_context
    EVP_PKEY *pkey = NULL, *params = NULL;
    /* NB: assumes pkey, peerkey have been already set up */

    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        return handle_parse_errors();

    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) 
        return handle_parse_errors();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) 
        return handle_parse_errors();

    /* Create the parameter object params */
    if(!EVP_PKEY_paramgen(pctx, &params)) 
        return handle_parse_errors();

    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) 
        return handle_parse_errors();

    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) 
        return handle_parse_errors();
    if(1 != EVP_PKEY_keygen(kctx, &pkey)) 
        return handle_parse_errors();

    /// not yet implemented. how to create peerkey?
    
    /* Get the peer's public key, and provide the peer with our public key -
     * how this is done will be specific to your circumstances */
    peerkey = get_peerkey(pkey);
    
    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) handleErrors();

    /* Initialise */
    if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();

    /* Provide the peer public key */
    if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) handleErrors();

    /* Determine buffer length for shared secret */
    if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) handleErrors();

    /* Create the buffer */
    if(NULL == (secret = OPENSSL_malloc(*secret_len))) handleErrors();

    /* Derive the shared secret */
    if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    /* Never use a derived secret directly. Typically it is passed
     * through some hash function to produce a key */
    return secret;
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

    /*
       mb_len = *d;
       d++;

       printf("PROCESSING: The Extension Length from ClientHello: %d\n", mb_len);
     */

    p = d;

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    /* Check group_id */
    s->mb_info.group_id = *p;

    if(s->mb_info.group_id != NID_X9_62_prime256v1) //SSL_CURVE_SECP256R1
    {
        return handle_parse_errors();
    }


    /* Check num_keys */
    p += 2;
    s->mb_info.num_keys = *p;

    if(p[0] < 1)
    {
        return handle_parse_errors();
    }


    /* Store hash of received keys (not yet) */
    p++;
    s->mb_info.mac_array = (unsigned char *)malloc(SHA256_DIGEST_LENGTH * s->mb_info.num_keys);

    SHA256_CTX ctx;
    uint8_t results[SHA256_DIGEST_LENGTH];
    unsigned char *buf = (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    int n;


    for(i=0; i<s->mb_info.num_keys; i--)
    {
        s->mb_info.key_length[i] = *p;
        p++;
        memcpy(buf, p, key_length[i]);
        *buf = ecdh(key_length[i], buf);

        n = strlen(buf);
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, (u_int8_t *)buf, n);
        SHA256_Final(results, &ctx);

        memcpy(s->mb_info.mac_array[SHA256_DIGEST_LENGTH * i], results, s->mb_info.key_length[i]);
        p += s->mb_info.key_length[i];
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

    if (p) {
    }

    // The total length of WarrantInfo message is 
    // group_id (2 bytes) + num_keys (1 byte) + mb_len (1 byte) + mb (mb_len bytes) 
    printf("PROGRESS: Set the length for the extension\n");
    //*len =;
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
