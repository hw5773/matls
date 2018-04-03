#ifndef __IP_OUT_H__
#define __IP_OUT_H__

#include <stdint.h>
#include "tcp_stream.h"
#include "mos_api.h"

extern inline int get_output_interface(uint32_t daddr);
void forward_ip_packet(mssl_manager_t mssl, struct pkt_ctx *pctx);
void forward_ipv4_packet(mssl_manager_t mssl, struct pkt_ctx *pctx);
uint8_t *ip_output_standalone(mssl_manager_t mssl,
    uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t tcplen,
    struct pkt_ctx *pctx, uint32_t cur_ts);
uint8_t *ip_output(mssl_manager_t mssl, tcp_stream *stream, uint16_t tcplen,
    struct pkt_ctx *pctx, uint32_t cur_ts);

#endif /* __IP_OUT_H__ */
