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

#define DEST1_MAC0 0x00
#define DEST1_MAC1 0x0c
#define DEST1_MAC2 0x29
#define DEST1_MAC3 0x6c
#define DEST1_MAC4 0x78
#define DEST1_MAC5 0x16

#define DEST2_MAC0 0x00
#define DEST2_MAC1 0x0c
#define DEST2_MAC2 0x29
#define DEST2_MAC3 0x1d
#define DEST2_MAC4 0xc4
#define DEST2_MAC5 0x78

int main(int argc, char *argv[])
{
  int sock1, sock2, ret, i, len, on = 1;
  int sockopt;
  int numbytes;
  struct ifreq if_opts1, if_opts2;
  struct ifreq if_mac1, if_mac2;
  struct ifreq if_idx1, if_idx2;
  uint8_t recv1[BUF_SIZE];
  uint8_t recv2[BUF_SIZE];
  uint8_t send1[BUF_SIZE];
  uint8_t send2[BUF_SIZE];
  char if_name1[IFNAMSIZ];
  char if_name2[IFNAMSIZ];
  struct sockaddr_ll dest1, dest2;

  if (argc == 3)
  {
    strcpy(if_name1, argv[1]);
    strcpy(if_name2, argv[2]);
  }
  else
  {
    perror("Enter two interfaces");
    perror("Usage: sudo ./middlebox <interface1> <interface2>");
    exit(EXIT_FAILURE);
  }

  struct ether_header *eh1 = (struct ether_header *) recv1;
  struct ether_header *eh2 = (struct ether_header *) recv2;
  struct iphdr *iph1 = (struct iphdr *) (recv1 + sizeof(struct ether_header));
  struct iphdr *iph2 = (struct iphdr *) (recv2 + sizeof(struct ether_header));
  struct tcphdr *tcph1 = (struct tcphdr *) (recv1 + sizeof(struct iphdr) + sizeof(struct ether_header));
  struct tcphdr *tcph2 = (struct tcphdr *) (recv2 + sizeof(struct iphdr) + sizeof(struct ether_header));

  printf("if_name1: %s\n", if_name1);
  printf("if_name2: %s\n", if_name2);

  if ((sock1 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
  {
    perror("listener: socket 1");
    return -1;
  }

  if ((sock2 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
  {
    perror("listener: socket 2");
    return -1;
  }

  strncpy(if_opts1.ifr_name, if_name1, IFNAMSIZ-1);
  strncpy(if_opts2.ifr_name, if_name2, IFNAMSIZ-1);
  ioctl(sock1, SIOCGIFFLAGS, &if_opts1);
  ioctl(sock2, SIOCGIFFLAGS, &if_opts2);
  if_opts1.ifr_flags |= IFF_PROMISC;
  if_opts2.ifr_flags |= IFF_PROMISC;
  ioctl(sock1, SIOCSIFFLAGS, &if_opts1);
  ioctl(sock2, SIOCSIFFLAGS, &if_opts2);
  strncpy(if_mac1.ifr_name, if_name1, IFNAMSIZ-1);
  strncpy(if_mac2.ifr_name, if_name2, IFNAMSIZ-1);
  ioctl(sock1, SIOCGIFHWADDR, &if_mac1);
  ioctl(sock2, SIOCGIFHWADDR, &if_mac2);
  strncpy(if_idx1.ifr_name, if_name1, IFNAMSIZ-1);
  strncpy(if_idx2.ifr_name, if_name2, IFNAMSIZ-1);
  ioctl(sock1, SIOCGIFINDEX, &if_idx1);
  ioctl(sock2, SIOCGIFINDEX, &if_idx2);

  if (setsockopt(sock1, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
  {
    perror("setsockopt");
    close(sock1);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock2, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1)
  {
    perror("setsockopt");
    close(sock2);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock1, SOL_SOCKET, SO_BINDTODEVICE, if_name1, IFNAMSIZ-1) == -1) 
  {
    perror("SO_BINDTODEVICE");
    close(sock1);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock2, SOL_SOCKET, SO_BINDTODEVICE, if_name2, IFNAMSIZ-1) == -1) 
  {
    perror("SO_BINDTODEVICE");
    close(sock2);
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
    numbytes = recvfrom(sock1, recv1, BUF_SIZE, MSG_DONTWAIT, NULL, NULL);
    
    if (numbytes > 0)
    {
      printf("listener1: got packet %d bytes\n", numbytes);
      eh1->ether_shost[0] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[0];
      eh1->ether_shost[1] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[1]; 
      eh1->ether_shost[2] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[2]; 
      eh1->ether_shost[3] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[3]; 
      eh1->ether_shost[4] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[4]; 
      eh1->ether_shost[5] = ((uint8_t *)&if_mac2.ifr_hwaddr.sa_data)[5]; 
    
      eh1->ether_dhost[0] = DEST2_MAC0;
      eh1->ether_dhost[1] = DEST2_MAC1;
      eh1->ether_dhost[2] = DEST2_MAC2;
      eh1->ether_dhost[3] = DEST2_MAC3;
      eh1->ether_dhost[4] = DEST2_MAC4;
      eh1->ether_dhost[5] = DEST2_MAC5;
      eh1->ether_type = htons(ETH_P_IP);

      memcpy(send2, recv1, numbytes);

      dest2.sll_ifindex = if_idx2.ifr_ifindex;
      dest2.sll_halen = ETH_ALEN;
      dest2.sll_addr[0] = DEST2_MAC0;
      dest2.sll_addr[1] = DEST2_MAC1;
      dest2.sll_addr[2] = DEST2_MAC2;
      dest2.sll_addr[3] = DEST2_MAC3;
      dest2.sll_addr[4] = DEST2_MAC4;
      dest2.sll_addr[5] = DEST2_MAC5;

      if (numbytes = (sendto(sock2, send2, numbytes, 0, (struct sockaddr *)&dest2, sizeof(struct sockaddr_ll))) < 0)
        perror("Failed to send");
      printf("Send from sock1 to sock2: %d\n", numbytes);
    }

    numbytes = recvfrom(sock2, recv2, BUF_SIZE, MSG_DONTWAIT, NULL, NULL);

    if (numbytes > 0)
    {
      printf("listener2: got packet %d bytes\n", numbytes);

      eh2->ether_shost[0] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[0]; 
      eh2->ether_shost[1] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[1]; 
      eh2->ether_shost[2] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[2]; 
      eh2->ether_shost[3] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[3]; 
      eh2->ether_shost[4] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[4]; 
      eh2->ether_shost[5] = ((uint8_t *)&if_mac1.ifr_hwaddr.sa_data)[5]; 
    
      eh2->ether_dhost[0] = DEST1_MAC0;
      eh2->ether_dhost[1] = DEST1_MAC1;
      eh2->ether_dhost[2] = DEST1_MAC2;
      eh2->ether_dhost[3] = DEST1_MAC3;
      eh2->ether_dhost[4] = DEST1_MAC4;
      eh2->ether_dhost[5] = DEST1_MAC5;
      eh2->ether_type = htons(ETH_P_IP);

      memcpy(send1, recv2, numbytes);

      dest1.sll_ifindex = if_idx1.ifr_ifindex;
      dest1.sll_halen = ETH_ALEN;
      dest1.sll_addr[0] = DEST1_MAC0;
      dest1.sll_addr[1] = DEST1_MAC1;
      dest1.sll_addr[2] = DEST1_MAC2;
      dest1.sll_addr[3] = DEST1_MAC3;
      dest1.sll_addr[4] = DEST1_MAC4;
      dest1.sll_addr[5] = DEST1_MAC5;

      if (numbytes = (sendto(sock1, send1, numbytes, 0, (struct sockaddr *)&dest1, sizeof(struct sockaddr_ll))) < 0)
        perror("Failed to send");
      printf("Send from sock2 to sock1: %d\n", numbytes);
    }

/*
    uint16_t proto;
    struct ether_header *eh = (struct ether_header *) recv;
    struct iphdr *iph = (struct iphdr *) (recv + sizeof(struct ether_header));
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
  close(sock1);
  close(sock2);
  return ret;
}
