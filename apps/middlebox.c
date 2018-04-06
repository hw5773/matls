#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEST_MAC0   0x00
#define DEST_MAC1   0x00
#define DEST_MAC2   0x00
#define DEST_MAC3   0x00
#define DEST_MAC4   0x00
#define DEST_MAC5   0x00

#define ETHER_TYPE  0x0800

#define DEFAULT_IF  "eth0"
#define BUF_SIZE    2048

int process_tcp(uint8_t *buf, int len);
void print_info(int ip, int port);

int main(int argc, char *argv[])
{
  int sock, ret, i;
  int sockopt;
  ssize_t numbytes;
  struct ifreq ifopts;
  struct ifreq if_ip;
  uint8_t buf[BUF_SIZE];
  char if_name[IFNAMSIZ];

  if (argc > 1)
    strcpy(if_name, argv[1]);
  else
    strcpy(if_name, DEFAULT_IF);

  struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));

  memset(&if_ip, 0, sizeof(struct ifreq));

  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) < 0)
  {
    perror("listener: socket");
    return -1;
  }

  strncpy(ifopts.ifr_name, if_name, IFNAMSIZ-1);
  ioctl(sock, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sock, SIOCSIFFLAGS, &ifopts);

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
  {
    perror("setsockopt");
    close(sock);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1) 
  {
    perror("SO_BINDTODEVICE");
    close(sock);
    exit(EXIT_FAILURE);
  }

repeat:
  printf("listener: Waiting to recvfrom...\n");
  numbytes = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);
  printf("listener: got packet %lu bytes\n", numbytes);

  if (iph->protocol == IPPROTO_TCP)
  {
    printf("This is TCP segment\n");
    process_tcp((uint8_t *)iph, iph->tot_len);
    goto repeat;
  }
  else if (iph->protocol == IPPROTO_UDP)
  {
    printf("This is UDP segment\n");
    goto repeat;
  }
  else if (iph->protocol == IPPROTO_ICMP)
  {
    printf("This is ICMP packet\n");
    goto repeat;
  }
  else 
  {
    printf("We don't what packet this is\n");
    goto repeat;
  }

done:
  goto repeat;

  close(sock);
  return ret;
}

int process_tcp(uint8_t *buf, int len)
{
  char sender[INET6_ADDRSTRLEN];
  struct iphdr *iph = (struct iphdr *) buf;
  struct tcphdr *tcph = (struct tcphdr *) (buf + sizeof(struct iphdr));

  printf("Source\n");
  print_info(iph->saddr, tcph->source);
  printf("Destination\n");
  print_info(iph->daddr, tcph->dest);

  return 1;
}

void print_info(int ip, int port)
{
  unsigned char ipb[4];
  ipb[0] = ip & 0xFF;
  ipb[1] = (ip >> 8) & 0xFF;
  ipb[2] = (ip >> 16) & 0xFF;
  ipb[3] = (ip >> 24) & 0xFF;
  printf("%d.%d.%d.%d:%d\n", ipb[0], ipb[1], ipb[2], ipb[3], port);
}
