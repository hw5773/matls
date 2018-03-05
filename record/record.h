/**
 * @file file.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define the attributes and functions for the record
 * chain
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

struct security_parameters
{
  int mac_length;
};

struct entry
{
  unsigned char *writer;
  unsigned char *prior_msg_hash;
  unsigned char *modification_hash;
};

struct modification_record
{
  unsigned char *endpoint_mac;
  TAILQ_ENTRY(entry) global_macs;
};

int init_mr();
int add_global_mac(unsigned char *record, int rec_len, unsigned char *id, int id_len, unsigned char *mac_key, int mk_len, unsigned char *prev, int prev_len, unsigned char *next, int next_len);
int verify_mr();
