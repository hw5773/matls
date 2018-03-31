#ifndef __ARP_H__
#define __ARP_H__

#include "mos_api.h"

#define MAX_ARPENTRY 1024
#define RUN_ARP 1
#define ARP_TIMEOUT_SEC 1

int init_arp_table();
unsigned char *gw_hwaddr(uint32_t ip);
unsigned char *get_destination_hwaddr(uint32_t dip);

void request_arp(mssl_manager_t mssl, uint32_t ip, int nif, uint32_t cur_ts);
int process_arp_packet(mssl_manager_t mtcp, uint32_t cur_ts, const int ifidx, unsigned char *pkt_data, int len);
void publish_arp(mssl_manager_t mssl);
void print_arp_table();
void forward_arp_packet(mssl_manager_t mssl, struct pkt_ctx *pctx);
void arp_timer(mssl_manager_t mssl, uint32_t cur_ts);

#endif /* __ARP_H__ */
