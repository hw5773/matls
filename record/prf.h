/**
 * @file prf.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define the attributes and functions for the
 * pseudorandom function
 */

#ifndef __PRF_H__
#define __PRF_H__

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <sys/time.h>

#include "logs.h"
#include "errors.h"

int a(int, unsigned char *);
int p_hash(unsigned char *, unsigned char *, unsigned char *);
int hmac_hash(unsigned char *, 
int prf(unsigned char *, unsigned char *, unsigned char *, unsigned char *);

#endif /* __PRF_H__ */
