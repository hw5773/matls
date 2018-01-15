/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

/* Add the client's mb */
int ssl_add_clienthello_mb_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen)
{
    printf("adding clienthello mb\n");
	*len = 0;
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
    printf("PROCESSING: The Extension Length from ClientHello: %d\n", len);

    // The value of the mb_len must be 0 for the intention
    // If not, it must be error
	
    printf("PROGRESS: Check whether the mb_len is zero\n");
    if (len != 0) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        return 0;
    }
    printf("PROCESSING: Confirm the mb_len is zero\n");
    
    // From the intention, the server enable the mb mode
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
    // mb_len (1 byte) + mb (mb_len bytes) + orig_cert (certificate chain bytes + length)
    // Need to check how to find the bytes of the certificates
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
