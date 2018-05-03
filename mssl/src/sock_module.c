#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
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
  unsigned char rcv_pktbuf[MAX_PKT_BURST][ETHERNET_FRAME_SIZE];
  int16_t rcv_pkt_len[MAX_PKT_BURST];
  uint16_t snd_pkt_size[MAX_DEVICES];
  uint8_t dev_poll_flag[MAX_DEVICES];
  uint8_t idel_poll_count;
  unsigned char hwaddr[MAX_DEVICES][ETH_ALEN];
  int if_idx[MAX_DEVICES];
} g_sock_ctx;

/**
 * @brief binding the socket context with the thread context
 */
void sock_init_handle(struct mssl_thread_context *ctx)
{
  //MA_LOG("Initialize the handler");
  ctx->io_private_context = &g_sock_ctx;
}

/*
 * @brief Getting the nic number from the socket
 */
int sock_get_nif(struct ifreq *ifr)
{
  int i;
  struct netdev_entry **ent = g_config.mos->netdev_table->ent;

  for (i=0; i<g_config.mos->netdev_table->num; i++)
    if (!strcmp(ifr->ifr_name, ent[i]->dev_name))
      return i;

  return -1;
}

/*
 * @brief Sending the packets in write buffers
 */
int sock_send_pkts(struct mssl_thread_context *ctx, int idx)
{
  //MA_LOG1s("Sending the packet to", g_config.mos->route_table->ent[idx]->dev_name);
  int i, len, sent, trial = 0, max_trial = 3;
  struct sock_private_context *spc = ctx->io_private_context;
  struct sockaddr_ll dest;
  len = spc->snd_pkt_size[idx];

  if (len == 0)
  {
    //MA_LOG("Packet length is 0");
    return 0;
  }

  //MA_LOG1s("Sending the packet to", g_config.mos->route_table->ent[idx]->dev_name);
#ifdef NETSTAT
  mssl->nstat.tx_packets[idx]++;
  mssl->nstat.tx_bytes[idx] += len + ETHER_OVR;
#endif /* NETSTAT */

  dest.sll_ifindex = spc->if_idx[idx];
  dest.sll_halen = ETH_ALEN;
  
  for (i=0; i<ETH_ALEN; i++)
    dest.sll_addr[i] = spc->snd_pktbuf[idx][i];

  //MA_LOGmac("Destination MAC", dest.sll_addr);

tx_again:
  if (sent = (sendto(spc->fd[idx], spc->snd_pktbuf[idx], len, MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll))) != len)
  {
    //MA_LOG1d("Send Failed, only sent", sent);
    trial += 1;
    if (trial < max_trial)
      goto tx_again;
  }

#ifdef NETSTAT
  // mssl->nstat.rx_errors[idx]++;
#endif /* NETSTAT */
  spc->snd_pkt_size[idx] = 0;

  return 1;
}

/*
 * @brief Receiving the packets from the socket and storing them into the read
 * buffer
 */
int sock_recv_pkts(struct mssl_thread_context *ctx, int ifidx)
{
  int i;
  if (ifidx < 0 || ifidx >= MAX_DEVICES)
    return -1;

  struct sock_private_context *spc = ctx->io_private_context;
  
  for (i=0; i<MAX_PKT_BURST; i++)
  {
    spc->rcv_pkt_len[i] = recvfrom(spc->fd[ifidx], spc->rcv_pktbuf[i], ETHERNET_FRAME_SIZE, MSG_DONTWAIT, NULL, NULL);

    if (spc->rcv_pkt_len[i] < 0)
      break;
//    else
//      MA_LOG1d("Received", spc->rcv_pkt_len[i]);
  }

  if (i > 0)
  {
//    MA_LOG1s("Received from", spc->dev_name[ifidx]);
//    MA_LOG1d("Num of Packets", i);
  }

  return i;
}

/*
 * @brief Getting the pointer to the buffer to be read
 */
uint8_t *sock_get_rptr(struct mssl_thread_context *ctx, int ifidx, int index, uint16_t *len)
{
//  MA_LOG1d("Getting packet pointer", index);
  struct sock_private_context *spc = ctx->io_private_context;
 // MA_LOG("Getting private_context success");
  if (spc->rcv_pkt_len[index] <= 0)
    return NULL;

  *len = spc->rcv_pkt_len[index];
 // MA_LOG1d("Length of packet", *len);
  return spc->rcv_pktbuf[index];
}

/*
 * @brief Getting the pointer to the buffer to be written
 */
uint8_t *sock_get_wptr(struct mssl_thread_context *ctx, int idx, uint16_t len)
{
  //MA_LOG1d("Getting write buffer pointer for the interface", idx);
  struct sock_private_context *spc = ctx->io_private_context;
  //MA_LOG("Getting private context success");
  if (spc->snd_pkt_size[idx] != 0)
    sock_send_pkts(ctx, idx);
  spc->snd_pkt_size[idx] = len;

  //MA_LOG("Getting socket success!");

  return (uint8_t *)spc->snd_pktbuf[idx];
}

/*
 * @brief Generating the sockets and making them be in promiscuous modes
 */
void sock_load_module_upper_half(void)
{
  int i, j, sockopt;
  int num_dev;
  struct netdev_entry **ent = g_config.mos->netdev_table->ent;
  struct ifreq if_opts, if_mac, if_idx;


  num_dev = g_config.mos->netdev_table->num;

  for (i=0; i<num_dev; i++)
  {
    if ((g_sock_ctx.fd[i] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
      perror("Socket generation failed");
      exit(EXIT_FAILURE);
    }
  }

  for (i=0; i<num_dev; i++)
  {
    g_sock_ctx.dev_name[i] = (char *)malloc(IFNAMSIZ);
    memcpy(g_sock_ctx.dev_name[i], ent[i]->dev_name, IFNAMSIZ-1);

    strncpy(if_opts.ifr_name, g_sock_ctx.dev_name[i], IFNAMSIZ-1);
    ioctl(g_sock_ctx.fd[i], SIOCGIFFLAGS, &if_opts);
    if_opts.ifr_flags |= IFF_PROMISC;
    ioctl(g_sock_ctx.fd[i], SIOCGIFFLAGS, &if_opts);
    strncpy(if_mac.ifr_name, g_sock_ctx.dev_name[i], IFNAMSIZ-1);
    ioctl(g_sock_ctx.fd[i], SIOCGIFHWADDR, &if_mac);
    strncpy(if_idx.ifr_name, g_sock_ctx.dev_name[i], IFNAMSIZ-1);
    ioctl(g_sock_ctx.fd[i], SIOCGIFINDEX, &if_idx);

    if (setsockopt(g_sock_ctx.fd[i], SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0)
    {
      perror("SO_REUSEADDR");
      goto err;
    }

    if (setsockopt(g_sock_ctx.fd[i], SOL_SOCKET, SO_BINDTODEVICE, g_sock_ctx.dev_name[i], IFNAMSIZ-1) < 0)
    {
      perror("SO_BINDTODEVICE");
      goto err;
    }

    for (j=0; j<ETH_ALEN; j++)
      g_sock_ctx.hwaddr[i][j] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[j];

    g_sock_ctx.if_idx[i] = if_idx.ifr_ifindex;
  }
  //MA_LOG("Sock module initialize success");
  return;
err:
  for (i=0; i<num_dev; i++)
    close(g_sock_ctx.fd[i]);
  exit(EXIT_FAILURE);
}

static void set_promisc(char *ifname)
{
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

/*
 * @brief Making nics to be in promiscuous mode.
 */
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
  .init_handle = sock_init_handle,
  .link_devices = NULL,
  .release_pkt = NULL,
  .send_pkts = sock_send_pkts,
  .get_wptr = sock_get_wptr,
  .set_wptr = NULL,
  .recv_pkts = sock_recv_pkts,
  .get_rptr = sock_get_rptr,
  .get_nif = sock_get_nif,
  .select = NULL,
  .destroy_handle = NULL,
  .dev_ioctl = NULL,
};
