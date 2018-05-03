#ifndef __ETH_OUT_H__
#define __ETH_OUT_H__

#include <stdint.h>

#include "mssl.h"
#include "tcp_stream.h"
#include "mos_api.h"

#define MAX_SEND_PCK_CHUNK 64

int flush_send_chunk_buf(mssl_manager_t mssl, int nif);
uint8_t *ethernet_output(mssl_manager_t mssl, struct pkt_ctx *pctx,
    uint16_t h_proto, int nif, unsigned char *dst_haddr, uint16_t iplen,
    uint32_t cur_ts);
void forward_ethernet_frame(mssl_manager_t mssl, struct pkt_ctx *pctx);

#endif /* __ETH_OUT_H__ */
