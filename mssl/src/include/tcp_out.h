#ifndef __TCP_OUT_H__
#define __TCP_OUT_H__

#include "mssl.h"
#include "tcp_stream.h"

enum ack_opt
{
  ACK_OPT_NOW,
  ACK_OPT_AGGREGATE,
  ACK_OPT_WACK,
};

int send_tcp_packet_standalone(mssl_manager_t mssl,
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport,
    uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags,
    uint8_t *payload, uint16_t payloadlen,
    uint32_t cur_ts, uint32_t echo_ts, uint16_t ip_id, int8_t in_ifidx);

int send_tcp_packet(mssl_manager_t mssl, tcp_stream *cur_stream,
    uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen);

extern inline int write_tcp_control_list(mssl_manager_t mssl,
    struct mssl_sender *sender, uint32_t cur_ts, int thresh);
extern inline int write_tcp_data_list(mssl_manager_t mssl, 
    struct mssl_sender *sender, uint32_t cur_ts, int thresh);
extern inline int write_tcp_ack_list(mssl_manager_t mssl,
    struct mssl_sender *sender, uint32_t cur_ts, int thresh);

extern inline void add_to_control_list(mssl_manager_t mssl,
    tcp_stream *cur_stream, uint32_t cur_ts);
extern inline void add_to_send_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void remove_from_control_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void remove_from_send_list(mssl_manager_t mssl, tcp_stream *cur_stream);
extern inline void remove_from_ack_list(mssl_manager_t mssl, tcp_stream *cur_stream);

extern inline void enqueue_ack(mssl_manager_t mssl, tcp_stream *cur_stream, 
    uint32_t cur_ts, uint8_t opt);

void update_passive_send_tcp_context(mssl_manager_t mssl, struct tcp_stream *cur_stream,
    struct pkt_ctx *pctx);

void post_send_tcp_action(mssl_manager_t mssl, struct pkt_ctx *pctx,
    struct tcp_stream *recvside_stream, struct tcp_stream *sendside_stream);

#endif /* __TCP_OUT_H__ */
