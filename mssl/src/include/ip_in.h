#ifndef __IP_IN_H__
#define __IP_IN_H__

#include "mssl.h"
#include "mssl_api.h"

int process_in_ipv4_packet(mssl_manager_t mssl, struct pkt_ctx *pctx);

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
  unsigned int sum;

  asm("  movl (%1), %0\n"
      "  subl $4, %2\n"
      "  jbe 2f\n"
      "  addl 4(%1), %0\n"
      "  adcl 8(%1), %0\n"
      "  adcl 12(%1), %0\n"
      "1: adcl 16(%1), %0\n"
      "  lea 4(%1), %1\n"
      "  decl %2\n"
      "  jne        1b\n"
      "  adcl $0, %0\n"
      "  movl %0, %2\n"
      "  shrl $16, %0\n"
      "  addw %w2, %w0\n"
      "  adcl $0, %0\n"
      "  notl %0\n"
      "2:"
      : "=r" (sum), "=r"(iph), "=r" (ihl)
      : "1" (iph), "2" (ihl)
      : "memory");
  return (__sum16)sum;
}

#endif /* __IP_IN_H__ */
