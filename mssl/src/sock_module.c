#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#include "include/io_module.h"
#include "include/mssl.h"
#include "include/config.h"
#include "include/logs.h"

#define MAX_PKT_BURST 64
#define ETHERNET_FRAME_SIZE 1514
#define MAX_IFNAMELEN (IF_NAMESIZE + 10)
#define EXTRA_BUFS 512
#define IDLE_POLL_WAIT 1
#define IDLE_POLL_COUNT 10

struct sock_private_context
{
  int fd[MAX_DEVICES];
  char *dev_name[MAX_DEVICES];
  unsigned char snd_pktbuf[MAX_DEVICES][ETHERNET_FRAME_SIZE];
  unsigned char *rcv_pktbuf[MAX_PKT_BURST];
  uint16_t rcv_pkt_len[MAX_PKT_BURST];
  uint16_t snd_pkt_size[MAX_DEVICES];
  uint8_t dev_poll_flag[MAX_DEVICES];
  uint8_t idel_poll_count;
} __attribute__((aligned(__WORDSIZE)));

int sock_get_nif(struct ifreq *ifr)
{
  int i;
  struct netdev_entry **ent = g_config.mos->netdev_table->ent;

  for (i=0; i<g_config.mos->netdev_table->num; i++)
    if (!strcmp(ifr->ifr_name, ent[i]->dev_name))
      return i;

  return -1;
}

void sock_load_module_upper_half(void)
{
  int i;
  int num_dev;
  uint64_t cpu_mask;
  int queue_range;

  num_dev = g_config.mos->netdev_table->num;

  for (i=0; i<num_dev; i++)
  {
    cpu_mask = g_config.mos->netdev_table->ent[i]->cpu_mask;
    queue_range = sizeof(cpu_mask) * NBBY - __builtin_clzll(cpu_mask);
    num_queues = (num_queues < queue_range) ? queue_range : num_queues;
    MA_LOG1d("num_queues", num_queues);
  }
}

static void set_promisc(char *ifname)
{
  MA_LOG1s("set_promisc", ifname);

  int fd, ret;
  struct ifreq eth;

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (fd < 0)
  {
    MA_LOG("Couldn't open socket!");
    return;
  }
  strcpy(eth.ifr_name, ifname);
  ret = ioctl(fd, SIOCGIFFLAGS, &eth);

  if (ret < 0)
  {
    MA_LOG1s("Get ioctl failed", ifname);
    close(fd);
    return;
  }

  if (eth.ifr_flags & IFF_PROMISC)
  {
    MA_LOG1s("Interface is already set to promiscuous", ifname);
    close(fd);
    return;
  }

  eth.ifr_flags |= IFF_PROMISC;

  ret = ioctl(fd, SIOCSIFFLAGS, &eth);
  if (ret < 0)
  {
    MA_LOG1s("Set ioctl failed", ifname);
    close(fd);
    return;
  }

  close(fd);
}

void sock_load_module_lower_half(void)
{
  struct netdev_entry **ent;
  int j;

  ent = g_config.mos->netdev_table->ent;

  for (j=0; j<g_config.mos->netdev_table->num; j++)
  {
    set_promisc(ent[j]->dev_name);
  }
}

io_module_func sock_module_func = 
{
  .load_module_upper_half = sock_load_module_upper_half,
  .load_module_lower_half = sock_load_module_lower_half,
  .init_handle = NULL,
  .link_devices = NULL,
  .release_pkt = NULL,
  .send_pkts = NULL,
  .get_wptr = NULL,
  .set_wptr = NULL,
  .recv_pkts = NULL,
  .get_rptr = NULL,
  .get_nif = sock_get_nif,
  .select = NULL,
  .destroy_handle = NULL,
  .dev_ioctl = NULL,
};
