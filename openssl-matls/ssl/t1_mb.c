
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
#include <pthread.h>

#include "ssl_locl.h"
#include "tls1.h"
#include "logs.h"
#include "matls.h"

#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "matls_func.h"

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
    int pub_length;
    int ext_len;
    struct keypair *keypair;

    s->mb_enabled = 0;

    MA_LOG("before if");

    if (p)
    {
      if (s->middlebox)
      {
        MA_LOG("Before waiting the message");
	      MSTART("Before waiting the message from the client", "server-side");
        while (!(s->pair && s->pair->extension_from_clnt_msg && (s->pair->extension_from_clnt_msg_len > 0))) { __sync_synchronize(); }
#ifdef STEP_CHECK
        printf("[step] after receiving extension message from the client: %lu\n", get_current_microseconds());
#endif /* STEP_CHECK */
	      MEND("After waiting the message from the client", "server-side");
        MA_LOG("The client side pair has the extension message");
        MA_LOG1d("before memcpy", s->pair->extension_from_clnt_msg_len);
        memcpy(p, s->pair->extension_from_clnt_msg, s->pair->extension_from_clnt_msg_len);
        free(s->pair->extension_from_clnt_msg);
        MA_LOG("after free");
      }

      group_id = s->mb_info.group_id;
      ctx = s->mb_info.bn_ctx;
      group = s->mb_info.group;
      pub_str = s->mb_info.pub_str;
      pub_length = s->mb_info.pub_length;

      if (!(s->mb_info.keypair))
      {
	      MSTART("Before busy waiting for lock", "client-side");
        pthread_mutex_lock(s->lockp);
	      MEND("After busy waiting for lock", "client-side");

        if (!(s->mb_info.keypair))
        {
          if (s->pair && s->pair->mb_info.keypair)
            s->mb_info.keypair = s->pair->mb_info.keypair;
          else
          {
            MA_LOG1d("before keypair in add client hello", s->server);
            make_keypair(&keypair, group, ctx);
            MA_LOG1d("after keypair in add client hello", s->server);
            s->mb_info.keypair = keypair;
            if (s->pair)
            {
              s->pair->mb_info.keypair = keypair;
              MA_LOG("pair gets keypair in add client hello");
            }
          }
        }
        pthread_mutex_unlock(s->lockp);
      }

      if (s->middlebox)
      {
        n2s(p, ext_len);
        p -= 2;
        ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length;
        s2n(ext_len, p);
        p += 2; // Group ID
        num_keys = *p;
        MA_LOG1d("before number of keys", (int)*p);
        *p = num_keys + 1;
        MA_LOG1d("after number of keys", (int)*p);
        p++;
        p += s->pair->extension_from_clnt_msg_len - 5;

        if (s->server_side)
        {
          *p = TYPE_SERVER_SIDE;
          p++;
          *len = s->pair->extension_from_clnt_msg_len + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
        }
        else
        {
          *p = TYPE_CLIENT_SIDE;
          p++;
          *len = s->pair->extension_from_clnt_msg_len + TYPE_LENGTH + META_LENGTH + pub_length;
        }
        s2n(pub_length, p);
        MA_LOG1d("Added Public Key Length", pub_length);
        memcpy(p, pub_str, pub_length);
        p += pub_length;

        MA_LOG1d("s->pair->extension_from_clnt_msg_len", s->pair->extension_from_clnt_msg_len);
        MA_LOG1d("length of client hello extension", *len);
      }
      else // Client
      {
        ext_len = GROUP_ID_LENGTH + NUM_OF_KEYS_INFO + TYPE_LENGTH + META_LENGTH + pub_length;
        MA_LOG1d("Extension Length", ext_len);
        s2n(ext_len, p);
        MA_LOG1d("Group ID", s->mb_info.group_id);
        s2n(s->mb_info.group_id, p);
        *(p++) = 1;
        *(p++) = TYPE_CLIENT;
        s2n(pub_length, p);
        memcpy(p, pub_str, pub_length);
        *len = ext_len + 2;
      }
    }

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
    MA_LOG("Parse client hello");
    // SSL_F_SSL_PARSE_CLIENTHELLO_MB_EXT

    unsigned char *p;
    int i, j, diff, slen, klen, nk, l, xlen;  // klen: key length, nk: number of keys, plen: EC point length
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

    if (s->middlebox)
    {
      MA_LOG("Copy this extension message to my SSL struct (not to pair)");
      s->extension_from_clnt_msg = (volatile unsigned char *)malloc(len);
	    MSTART("Copy the extension message to my SSL struct (not to pair)", "client-side");
      memcpy(s->extension_from_clnt_msg, d, len);
      s->extension_from_clnt_msg_len = len;
	    MEND("Complete to copy the extension message to my SSL struct (not to pair)", "client-side");
    }

    p = d;
#ifdef DEBUG
    int ext_len;
    n2s(p, ext_len);
    MA_LOG1d("Received Extension Length", ext_len);
#else
    p += 2;
#endif /* DEBUG */

    /* message: group_id(2bytes) + num_keys(1byte) + (key length(1byte) and key value) list */

    n2s(p,s->mb_info.group_id);

    MA_LOG1d("Group ID", s->mb_info.group_id);
    group = s->mb_info.group;

/*
    switch(s->mb_info.group_id)
    {
    case SSL_CURVE_SECP256R1:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    default:
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    }
*/

    /* Check num_keys */
    nk = s->mb_info.num_keys = *(p++);
    MA_LOG1d("Number of Keys (nk)", nk);

    if (s->middlebox) // middlebox, index 0: client->server, index 1: server->client
    {
      nk = 2;
      s->mb_info.key_length = (int *)calloc(2, sizeof(int));
      s->mb_info.secret = (volatile unsigned char **)calloc(2, sizeof(unsigned char *));
      s->mb_info.mac_array = (unsigned char **)calloc(2, sizeof(unsigned char *));
    }
    else
    {
      s->mb_info.key_length = (int *)calloc(nk, sizeof(int));
      s->mb_info.secret = (volatile unsigned char **)calloc(nk, sizeof(unsigned char *));
      s->mb_info.mac_array = (unsigned char **)calloc(nk, sizeof(unsigned char *));
    }

    for (i=0; i<nk; i++)
    {
      s->mb_info.mac_array[i] = (unsigned char *)malloc(SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
    }
    MA_LOG1d("Number of Keys (nk, revised?)", nk);

    if(nk < 1)
    {
        return handle_parse_errors();
    }

    ctx = BN_CTX_new();
    x = BN_new();
    y = BN_new();

    if (!(s->mb_info.keypair))
    {
      if (s->middlebox)
      {
	      MSTART("Before busy waiting for lock", "client-side");
	      MEND("After busy waiting for lock", "client-side");
        pthread_mutex_lock(s->lockp);
        if (!(s->mb_info.keypair))
        {
          if (s->pair && s->pair->mb_info.keypair)
            s->mb_info.keypair = s->pair->mb_info.keypair;
          else
          {
            MA_LOG1d("before make_keypair in parse client hello as a middlebox", s->server);
            make_keypair(&keypair, group, ctx);
            MA_LOG1d("before make_keypair in parse client hello as a middlebox", s->server);
            s->mb_info.keypair = keypair;
            if (s->pair)
            {
              s->pair->mb_info.keypair = keypair;
              MA_LOG("pair gets keypair in parse client hello");
            }
          }
        }
        pthread_mutex_unlock(s->lockp);
      }
      else
      {
        MA_LOG1d("before make_keypair in parse client hello as an endpoint", s->server);
        make_keypair(&keypair, group, ctx);
        MA_LOG1d("before make_keypair in parse client hello as an endpoint", s->server);
        s->mb_info.keypair = keypair;
      }
    }
    MA_LOG1p("s->mb_info.keypair", s->mb_info.keypair);
    keypair = s->mb_info.keypair;

    int end;
    if (s->middlebox)
      end = 1;
    else
      end = nk;

    for (i=0; i<end; i++)
    {
      secret = EC_POINT_new(group);

      if (*p != TYPE_CLIENT_SIDE)
      {
        MA_LOG1d("Wrong Type", *p);
      }

      p++;
      n2s(p, klen);

      s->mb_info.key_length[i] = klen;
      peer_str = (unsigned char *)malloc(klen);

      if (i == CLIENT)
      {
        s->mb_info.random[CLIENT] = (unsigned char *)malloc(klen);
        memcpy(s->mb_info.random[CLIENT], p, klen);
      }

      memcpy(peer_str, p, klen);
      p += klen;

      peer_pub = EC_POINT_new(group);
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_1S);
      char_to_pub(peer_str, klen, peer_pub, group, ctx);
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_1E);
      //INTERVAL(time_log, SERVER_CLIENT_HELLO_1S, SERVER_CLIENT_HELLO_1E);

      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_2S);
      EC_POINT_mul(group, secret, NULL, peer_pub, keypair->pri, ctx);
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_2E);
      //INTERVAL(time_log, SERVER_CLIENT_HELLO_2S, SERVER_CLIENT_HELLO_2E);

      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_3S);
      EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_3E);
      //INTERVAL(time_log, SERVER_CLIENT_HELLO_3S, SERVER_CLIENT_HELLO_3E);

      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_4S);
      xlen = (klen - 1) / 2;
      secret_str = (unsigned char *)malloc(xlen);
      l = BN_bn2bin(x, secret_str);
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_4E);
      //INTERVAL(time_log, SERVER_CLIENT_HELLO_4S, SERVER_CLIENT_HELLO_4E);

      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_5S);
      if (l < xlen)
      {
        diff = xlen - l;
        for (j=xlen-1; j>=diff; j--)
          secret_str[j] = secret_str[j-diff];
        for (j=diff-1; j>=0; j--)
          secret_str[j] = 0;
      }
      //RECORD_LOG(time_log, SERVER_CLIENT_HELLO_5E);
      //INTERVAL(time_log, SERVER_CLIENT_HELLO_5S, SERVER_CLIENT_HELLO_5E);

      s->mb_info.secret[i] = (volatile unsigned char *)secret_str;

      free(peer_str);
      EC_POINT_free(secret);
      EC_POINT_free(peer_pub);
    }

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
  MA_LOG("adding serverhello mb");

	int group_id = s->mb_info.group_id;
	int num_keys = 1;
	EC_GROUP *group = s->mb_info.group;
	BN_CTX *ctx = s->mb_info.bn_ctx;
	unsigned char *pub_str = s->mb_info.pub_str;
  int pub_length = s->mb_info.pub_length;
  struct keypair *keypair = s->mb_info.keypair;
	int i, ext_len;

  /*
  switch(group_id)
  {
  case SSL_CURVE_SECP256R1:
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  default:
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  }

  ctx = BN_CTX_new();
  */

  if (p) {
    if (!(s->mb_info.keypair))
    {
	    MSTART("Before busy waiting for lock", "client-side");
	    MEND("After busy waiting for lock", "client-side");
      pthread_mutex_lock(s->lockp);
      if (!(s->mb_info.keypair))
      {
        if (s->pair && s->pair->mb_info.keypair)
          s->mb_info.keypair = s->pair->mb_info.keypair;
        else
        {
          MA_LOG1d("before keypair in add server hello", s->server);
          make_keypair(&keypair, group, ctx);
          MA_LOG1d("after keypair in add server hello", s->server);
          s->mb_info.keypair = keypair;
          if (s->pair)
          {
            s->pair->mb_info.keypair = keypair;
            MA_LOG("pair gets key pair in add_server_hello");
          }
        }
      }
      pthread_mutex_unlock(s->lockp);
    }

    if (s->middlebox)
    {
      int tmp1;
      MA_LOG("Before waiting the message");
      MSTART("Before waiting the message", "client-side");
      while (!(s->pair && (s->pair->extension_from_srvr_msg_len > 0))) { __sync_synchronize(); }
#ifdef STEP_CHECK
      printf("[step] after receiving extension message from the server: %lu\n", get_current_microseconds());
#endif /* STEP_CHECK */
      MEND("The server side pair has the extension message", "client-side");
      MA_LOG("The server side pair has the extension message");

      MA_LOG1d("before memcpy", s->pair->extension_from_srvr_msg_len);
      memcpy(p, s->pair->extension_from_srvr_msg, s->pair->extension_from_srvr_msg_len);
      free(s->pair->extension_from_srvr_msg);
      MA_LOG("after free");
      n2s(p, ext_len);
      MA_LOG1d("ext_len", ext_len);
      p -= 2;

	    if (s->server_side)
		    ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
	    else
      	ext_len = ext_len + TYPE_LENGTH + META_LENGTH + pub_length;
	  
      s2n(ext_len, p);

      n2s(p, tmp1);
      MA_LOG1d("Received Group ID", tmp1);

      num_keys = *p;
      *p = num_keys + 1;
      MA_LOG1d("num keys after", (*p));
      p++;
      p += s->pair->extension_from_srvr_msg_len - 5;

	    if (s->server_side)
	    {
		    *p = TYPE_SERVER_SIDE;
		    p++;
		    *len = s->pair->extension_from_srvr_msg_len + TYPE_LENGTH + META_LENGTH + pub_length + META_LENGTH + s->proof_length;
	    }
	    else
	    {
		    *p = TYPE_CLIENT_SIDE;
		    p++;
		    *len = s->pair->extension_from_srvr_msg_len + TYPE_LENGTH + META_LENGTH + pub_length;
	    }

      s2n(pub_length, p);
      memcpy(p, pub_str, pub_length);
	    p += pub_length;

	    if (s->server_side)
	    {
		    s2n(s->proof_length, p);
		    memcpy(p, s->proof, s->proof_length);
	    }
    }
    else
    {
      ext_len = META_LENGTH + 1 + TYPE_LENGTH + META_LENGTH + pub_length;
      s2n(ext_len, p);
	    s2n(group_id, p);
	    *(p++) = num_keys;
	    *(p++) = TYPE_SERVER;
	    s2n(pub_length, p); //pubkey_len
	    memcpy(p, pub_str, pub_length); //pubkey
      p += pub_length;
      *len = META_LENGTH + META_LENGTH + 1 + TYPE_LENGTH + META_LENGTH + pub_length;
	  }

    PRINTK("MB Pubkey", pub_str, pub_length);
    unsigned char *tmp = (unsigned char *)malloc(SECRET_LENGTH);

    if (s->middlebox)
    {
      for (i=0; i<2; i++)
      {
        if (i==0)
          MA_LOG("Client");
        else
          MA_LOG("Server");

    		MSTART("Before busy waiting for accountability key", "client-side");
        while (!s->mb_info.secret[i]) {}
		    MEND("After busy waiting for accountability key", "client-side");
        //memcpy(tmp, s->mb_info.secret[i], SECRET_LENGTH);

        t1_prf(TLS_MD_ACCOUNTABILITY_KEY_CONST, TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE,
                s->mb_info.random[SERVER], s->mb_info.key_length[SERVER],
                s->mb_info.random[CLIENT], s->mb_info.key_length[CLIENT],
                NULL, 0, NULL, 0,
                s->mb_info.secret[i], SECRET_LENGTH,
                s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH); //LENGTH: 32

        PRINTK("Server Random", s->mb_info.random[SERVER], s->mb_info.key_length[SERVER]);
        PRINTK("Client Random", s->mb_info.random[CLIENT], s->mb_info.key_length[CLIENT]);
        PRINTK("Secret", s->mb_info.secret[i], SECRET_LENGTH);
        PRINTK("Accountability Key", s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      }
    }
    else
    {
      for (i=0; i<s->mb_info.num_keys; i++)
      {
        memcpy(tmp, s->mb_info.secret[i], SECRET_LENGTH);

        t1_prf(TLS_MD_ACCOUNTABILITY_KEY_CONST, TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE,
                pub_str, pub_length,
                s->mb_info.random[CLIENT], s->mb_info.key_length[CLIENT],
                NULL, 0, NULL, 0,
                s->mb_info.secret[i], SECRET_LENGTH,
                s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH); //LENGTH: 32

        PRINTK("Server Random", pub_str, pub_length);
        PRINTK("Client Random", s->mb_info.random[CLIENT], s->mb_info.key_length[CLIENT]);
        PRINTK("Secret", tmp, SECRET_LENGTH);
        PRINTK("Accountability Key", s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
      }
    }
  }

  MA_LOG("Set the length for the extension matls");

  MA_LOG1d("Complete Setting the length for the extension", *len);

  return 1;
}

/*
 * Parse the server's mb and abort if it's not right
 */
int ssl_parse_serverhello_mb_ext(SSL *s, unsigned char *d, int size, int *al)
{
  unsigned char *p;
  unsigned char *secret_str, *peer_str;
  struct keypair *keypair;
  int i, j, diff, klen, ext_len, group_id, num_keys, type, xlen, len, end;
  SSL *tmp;
  EC_GROUP *group;
  BIGNUM *x, *y;
  EC_POINT *secret, *peer_pub;
  BN_CTX *ctx;

  if (size < 0)
  {
    return handle_parse_errors();
  }

  if (s->middlebox)
    tmp = s->pair;
  else // Client
    tmp = s;

  group = tmp->mb_info.group;
  keypair = tmp->mb_info.keypair;

  p = d;
  n2s(p, ext_len);
  MA_LOG1d("ext_len", ext_len);
  n2s(p, group_id);
  MA_LOG1d("Received Group ID", group_id);

  num_keys = *(p++);
  MA_LOG1d("Number of Keys", num_keys);
  s->mb_info.num_keys = num_keys;

  if (s->middlebox)
  {
    s->pair->mb_info.num_keys = num_keys;
    end = 1;
  }
  else // Client
  {
    end = num_keys;
    s->mb_info.key_length = (int *)calloc(num_keys, sizeof(int));
    s->mb_info.secret = (volatile unsigned char **)calloc(num_keys, sizeof(unsigned char *));
    s->mb_info.mac_array = (unsigned char **)calloc(num_keys, sizeof(unsigned char *));

    for (i=0; i<num_keys; i++)
      s->mb_info.mac_array[i] = (unsigned char *)malloc(SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
  }

  for (i=0; i<num_keys; i++)
  {
    x = BN_new();
    y = BN_new();
    secret = EC_POINT_new(group);

    type = *(p++);

    MA_LOG1d("Received Type", type);
    n2s(p, klen);
    MA_LOG1d("Received Key Length", klen);

    if (s->middlebox)
      tmp->mb_info.key_length[SERVER] = klen;
    else
      tmp->mb_info.key_length[i] = klen;

    peer_str = (unsigned char *)malloc(klen);
    memcpy(peer_str, p, klen);

    if (i == 0)
    {
      tmp->mb_info.random[SERVER] = (unsigned char *)malloc(klen);
      if (s->middlebox)
        tmp->mb_info.key_length[SERVER] = klen;
      PRINTK("Server DH Public", peer_str, klen);
      memcpy(tmp->mb_info.random[SERVER], p, klen);
    }

    p += klen;

    peer_pub = EC_POINT_new(group);
    char_to_pub(peer_str, klen, peer_pub, group, ctx);
    EC_POINT_mul(group, secret, NULL, peer_pub, keypair->pri, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
    xlen = (klen - 1) / 2;
    secret_str = (unsigned char *)malloc(xlen);
    len = BN_bn2bin(x, secret_str);

    if (len < xlen)
    {
      diff = xlen - len;

      for (j=xlen-1; j>=diff; j--)
        secret_str[j] = secret_str[j-diff];

      for (j=diff-1; j>=0; j--)
        secret_str[j] = 0;
    }

    if (s->middlebox)
      tmp->mb_info.secret[SERVER] = secret_str;
    else
      tmp->mb_info.secret[i] = secret_str;

    MA_LOG1d("Index", i);
    PRINTK("Secret", tmp->mb_info.secret[i], SECRET_LENGTH);

    if (s->middlebox)
    {
      MA_LOG1d("Before malloc for extension from srvr msg", size);
      MSTART("Before malloc for extension from server message", "client-side");
      s->extension_from_srvr_msg = (volatile unsigned char *)malloc(size);
      MEND("After malloc for extension from server message", "client-side");
      MA_LOG("After malloc for extension from srvr msg");
      memcpy(s->extension_from_srvr_msg, d, size);
      s->extension_from_srvr_msg_len = size;
    }

    free(peer_str);
    EC_POINT_free(peer_pub);
    EC_POINT_free(secret);
    BN_free(x);
    BN_free(y);
  }

  if (!s->middlebox)
  {
    PRINTK("Server Random", s->mb_info.random[SERVER], s->mb_info.key_length[0]);
    PRINTK("Client Random", s->mb_info.pub_str, s->mb_info.pub_length);
    
    for (i=0; i<end; i++)
    {
      PRINTK("Secret", s->mb_info.secret[i], SECRET_LENGTH);
      MA_LOG1p("mac_array[i]", s->mb_info.mac_array[i]);
      MA_LOG1s("TLS_MD_ACCOUNTABILITY_KEY_CONST", TLS_MD_ACCOUNTABILITY_KEY_CONST);
      MA_LOG1d("TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE", TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE);
      t1_prf(TLS_MD_ACCOUNTABILITY_KEY_CONST, TLS_MD_ACCOUNTABILITY_KEY_CONST_SIZE,
        s->mb_info.random[SERVER], s->mb_info.key_length[0],
        s->mb_info.pub_str, s->mb_info.pub_length,
        NULL, 0, NULL, 0,
        s->mb_info.secret[i], SECRET_LENGTH,
        s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);

      PRINTK("Accountability Key", s->mb_info.mac_array[i], SSL_MAX_ACCOUNTABILITY_KEY_LENGTH);
    }
  }
  s->mb_enabled = 1;

  MA_LOG("Finished Serverhello Extension");

  return 1;
}
