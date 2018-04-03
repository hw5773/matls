#ifndef __TCP_H__
#define __TCP_H__

#include "tcp_stream.h"
#include "mos_api.h"
#include "mssl.h"

extern inline void fill_packet_context_tcp_info(struct pkt_ctx *pctx, struct tcphdr *tcph);
extern inline void fill_flow_context(struct pkt_ctx *pctx, tcp_stream *cur_stream, int cpu);
extern inline void handle_single_callback(mssl_manager_t mssl, uint32_t hooking_point,
    struct pkt_ctx *pctx, uint64_t events);
int process_in_tcp_packet(mssl_manager_t mssl, struct pkt_ctx *pctx);
void update_monitor(mssl_manager_t mssl, struct tcp_stream *sendside_stream,
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx, bool is_pkt_reception);
#endif /* __TCP_H__ */
