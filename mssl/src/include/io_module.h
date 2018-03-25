#ifndef __IO_MODULE_H__
#define __IO_MODULE_H__

#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdint.h>

struct mssl_thread_context;

typedef struct io_module_func
{
  void (*load_module_upper_half)(void);
  void (*load_module_lower_half)(void);
  void (*init_handle)(struct mssl_thread_context *ctx);
  int32_t (*link_devices)(struct mssl_thread_context *ctx);
  void (*release_pkt)(struct mssl_thread_context *ctx);
  uint8_t *(*get_wptr)(struct mssl_thread_context *ctx, int ifidx, uint16_t len);
  void (*set_wptr)(struct mssl_thread_context *ctx, int out_ifidx, int in_ifidx, int idx);
  int32_t (*send_pkts)(struct mssl_thread_context *ctx, int nif);
  uint8_t * (*get_rptr)(struct mssl_thread_context *ctx, int ifidx, int index, uint16_t *len);
  int (*get_nif)(struct ifreq *ifr);
  int32_t (*recv_pkts)(struct mssl_thread_context *ctx, int ifidx);
  int32_t (*select)(struct mssl_thread_context *ctx);
  void (*destroy_handle)(struct mssl_thread_context *ctx);
  int32_t (*dev_ioctl)(struct mssl_thread_context *ctx, int nif, int cmd, void *argp);
} io_module_func __attribute__((aligned(__WORDSIZE)));

io_module_func *current_iomodule_func;
typedef struct
{
  int8_t pktidx;
  uint32_t hash_value;
} rss_info;

#define MAX_DEVICES 16
#define DPDK_STR "dpdk"
#define PCAP_STR "pcap"
#define NETMAP_STR "netmap"

#define PKT_TX_IP_CSUM 0x01
#define PKT_TX_TCP_CSUM 0x02
#define PKT_RX_RSS 0x03
#define DRV_NAME 0x08

extern io_module_func sock_module_func;

#endif /* __IO_MODULE_H__ */
