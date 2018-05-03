#ifndef __ETH_IN_H__
#define __ETH_IN_H__

#include "mssl.h"

int process_packet(mssl_manager_t mssl, const int ifidx, const int index, uint32_t cur_ts, unsigned char *pkt_data, int len);

#endif /* __ETH_IN_H__ */
