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

struct record
{

};

int init_record();
int add_record(unsigned char *record, int rec_len, unsigned char *id, int id_len, unsigned char *mac_key, int mk_len, unsigned char *prev, int prev_len, unsigned char *next, int next_len);
int verify_block();
