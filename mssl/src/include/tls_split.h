#include "mssl.h"
#include "mos_api.h"
#include "tcp_stream.h"

void do_split_session(mssl_manager_t mssl, struct tcp_stream *sendside_stream, 
    struct tcp_stream *recvside_stream, struct pkt_ctx *pctx);
