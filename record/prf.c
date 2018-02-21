/** 
 * @file prf.c
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to implement the prf
 */

int prf(unsigned char *secret, unsigned char *label, unsigned char *seed, unsigned char *ret)
{
  APP_LOG("prf");
