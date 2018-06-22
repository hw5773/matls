#ifndef __MATLS_H__
#define __MATLS_H__

#define TYPE_LENGTH 1
#define META_LENGTH 2

#define TYPE_DUMMY 0
#define TYPE_SERVER 1
#define TYPE_CLIENT_SIDE 1
#define TYPE_SERVER_SIDE 2
#define TYPE_CLIENT_SIDE_WITH_SCT 3
#define TYPE_SERVER_SIDE_WITH_SCT 4

#define TLS_MD_ID_SIZE 32
#define TLS_MD_HASH_SIZE 32
#define TLS_MD_HMAC_SIZE 32

#define SSL_MAX_ACCOUNTABILITY_KEY_LENGTH 32
#define SSL_MAX_GLOBAL_MAX_KEY_LENGTH 32

#define SSL_CURVE_SECP256R1 23
#define SECP256r1_PUBKEY_LENGTH 64
#define SECRET_LENGTH 32
#define CLIENT 0
#define SERVER 1

#define MATLS_VERSION_LENGTH 2
#define MATLS_CIPHERSUITE_LENGTH 2
#define MATLS_TRANSCRIPT_LENGTH s->s3->tmp.finish_md_len

#define MATLS_M_LENGTH (MATLS_VERSION_LENGTH + MATLS_CIPHERSUITE_LENGTH + MATLS_TRANSCRIPT_LENGTH)
#define MATLS_M_PAIR_LENGTH (MATLS_VERSION_LENGTH + MATLS_CIPHERSUITE_LENGTH + s->pair->s3->tmp.finish_md_len)
#define MATLS_H_LENGTH 32

int idx;

#ifdef DEBUG
#define PRINTK(msg, arg1, arg2) \
  fprintf(stderr, "[matls] %s: %s (%d bytes) \n", __func__, msg, arg2); \
  for (idx=0; idx<arg2; idx++) \
  { \
    if (idx % 10 == 0) \
      fprintf(stderr, "\n"); \
    fprintf(stderr, "%02X ", arg1[idx]); \
  } \
  fprintf(stderr, "\n");
#else
#define PRINTK(msg, arg1, arg2)
#endif /* DEBUG */

extern int lock;

#endif /* __MATLS_H__ */
