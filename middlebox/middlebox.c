/**
 * @file middlebox.c
 * @author Hyunwoo Lee
 * @date 12 Jan 2018
 * @brief This file is the main of the middlebox
 */

#include "middlebox.h"
#include "packet.h"
#include "mb_log.h"
#include "pair_repo.h"

#define ETHER_TYPE  0x0800

#define DEST_MAC0 0x2c
#define DEST_MAC1 0x4d
#define DEST_MAC2 0x54
#define DEST_MAC3 0x44
#define DEST_MAC4 0x78
#define DEST_MAC5 0x75

int main(int argc, char *argv[])
{
  int sock, ret, i, len, on = 1;
  int sockopt;
  int numbytes;
  struct ifreq ifopts;
  struct ifreq if_ip;
  uint8_t recv[BUF_SIZE];
  uint8_t send[BUF_SIZE];
  char if_name[IFNAMSIZ];

  if (argc > 1)
    strcpy(if_name, argv[1]);
  else
    strcpy(if_name, DEFAULT_IF);

  struct ether_header *eh = (struct ether_header *) recv;
  struct iphdr *iph = (struct iphdr *) (recv + sizeof(struct ether_header));
  struct tcphdr *tcph = (struct tcphdr *) (recv + sizeof(struct iphdr) + sizeof(struct ether_header));

  printf("if_name: %s\n", if_name);
  memset(&if_ip, 0, sizeof(struct ifreq));

  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
  {
    perror("listener: socket 1");
    return -1;
  }

  strncpy(ifopts.ifr_name, if_name, IFNAMSIZ-1);
  ioctl(sock, SIOCGIFFLAGS, &ifopts);
//  ifopts.ifr_flags |= IFF_PROMISC;
//  ioctl(sock, SIOCSIFFLAGS, &ifopts);

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
  {
    perror("setsockopt");
    close(sock);
    exit(EXIT_FAILURE);
  }

  //if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1) 
  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ-1) == -1) 
  {
    perror("SO_BINDTODEVICE");
    close(sock);
    exit(EXIT_FAILURE);
  }
/*
  if (init_repo_table() < 0)
  {
    perror("Error while initializeing pair entry repository table");
    exit(EXIT_FAILURE);
  }
*/
  while (1)
  {
    MB_LOG("listener: Waiting to recvfrom...");
    numbytes = recvfrom(sock, recv, BUF_SIZE, 0, NULL, NULL);
    printf("listener: got packet %d bytes\n", numbytes);

    if (eh->ether_dhost[0] == DEST_MAC0 &&
        eh->ether_dhost[1] == DEST_MAC1 &&
        eh->ether_dhost[2] == DEST_MAC2 &&
        eh->ether_dhost[3] == DEST_MAC3 &&
        eh->ether_dhost[4] == DEST_MAC4 &&
        eh->ether_dhost[5] == DEST_MAC5)
    {
      printf("Correct destination MAC address\n");
    }
    else
    {
      printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
          eh->ether_dhost[0],
          eh->ether_dhost[1],
          eh->ether_dhost[2],
          eh->ether_dhost[3],
          eh->ether_dhost[4],
          eh->ether_dhost[5]);
      ret = -1;
      goto done;
    }

/*
    uint16_t proto;
    struct ethhdr *eh = (struct ethhdr *) recv;
    struct iphdr *iph = (struct iphdr *) (recv + sizeof(struct ethhdr));
    // Check whether the transport layer protocol for the packet
    struct tcphdr *tcph = (struct tcphdr *)(recv + iph->ihl * 4);
    proto = ntohs(eh->h_proto);
    len = ntohs(iph->tot_len);

    //if (check_checksum(recv, len) < 0) continue;
    struct pair_entry *tmp = (struct pair_entry *)malloc(sizeof(struct pair_entry));
    if (parse_entry(tmp, recv, len) < 0) continue;

    if (tcph->syn)
    {
      MB_LOG("SYN packet");

      if (ntohs(tcph->dest) == 80)
        MB_LOG("http message");
    }

    MB_LOGip("Source IP", tmp->saddr);
    MB_LOGip("Dest IP", tmp->daddr);

    int ipl = iph->ihl * 4;
    int tl = len - ipl;

    if (add_pair_to_table(tmp) < 0) continue;
    if (process_packet(tmp, iph, ipl, tcph, tl, send, &len) < 0) continue;

    struct sockaddr_in s;
    s.sin_family = AF_INET;
    s.sin_port = tcph->source;
    s.sin_addr.s_addr = iph->saddr;
    numbytes = sendto(sock, send, len, 0, (struct sockaddr *)&s, sizeof(s));
    MB_LOG1d("listener: sent packet", numbytes);
    tcph = (struct tcphdr *) (send + ipl);
    MB_LOG1x("SYN packet?", tcph->syn);
    MB_LOG1x("ACK packet?", tcph->ack);
*/
  }

done:
  close(sock);
  return ret;
}
