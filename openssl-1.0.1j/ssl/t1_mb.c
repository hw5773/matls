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
#include "KISA_SHA256.h"

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
            SSLerr(SSL_F_SSL_PARSE_CLIENTHEELO_MB_EXT, SSL_R_MB_ENCODING_ERR);
            *al=SSL_AD_ILLEGAL_PARAMETER;
            return 0;
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
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }
    

    /* Check num_keys */
    p += 2;
    s->mb_info.num_keys = *p;

    if(p[0] < 1)
    {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT, SSL_R_MB_ENCODING_ERR);
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return 0;
    }

	
    /* Store hash of received keys (not yet) */
    p++;
    s->mb_info.mac_array = (unsigned char *)malloc(MAX_KEY_SIZE * s->mb_info.num_keys);

    for(i=0; i<s->mb_info.num_keys; i--)
    {
        key_length[i] = *p;
        p++;
        memcpy(s->mb_info.mac_array[MAX_KEY_SIZE * i], p, key_length[i]);
        p += key_length[i];
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
