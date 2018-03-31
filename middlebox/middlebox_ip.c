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

int main(int argc, char *argv[])
{
  int sock1, sock2, ret, i, len, on = 1;
  int sockopt;
  int numbytes;
  uint8_t recv1[BUF_SIZE];
  uint8_t recv2[BUF_SIZE];
  uint8_t send1[BUF_SIZE];
  uint8_t send2[BUF_SIZE];
  char if_name1[IFNAMSIZ];
  char if_name2[IFNAMSIZ];
  struct sockaddr_in dest1, dest2;

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

  struct iphdr *iph1 = (struct iphdr *) recv1;
  struct iphdr *iph2 = (struct iphdr *) recv2;
  struct tcphdr *tcph1 = (struct tcphdr *) (recv1 + sizeof(struct iphdr));
  struct tcphdr *tcph2 = (struct tcphdr *) (recv2 + sizeof(struct iphdr));

  printf("if_name1: %s\n", if_name1);
  printf("if_name2: %s\n", if_name2);

  if ((sock1 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
  {
    perror("listener: socket 1");
    return -1;
  }

  if ((sock2 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
  {
    perror("listener: socket 2");
    return -1;
  }

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

      dest2.sin_port = tcph1->dest;
      dest2.sin_addr.s_addr = iph1->daddr;
      memcpy(send2, recv1, numbytes);

      if (numbytes = (sendto(sock2, send2, numbytes, 0, (struct sockaddr *)&dest2, sizeof(struct sockaddr_in))) < 0)
        perror("Failed to send");
      printf("Send from sock1 to sock2: %d\n", numbytes);
    }

    numbytes = recvfrom(sock2, recv2, BUF_SIZE, MSG_DONTWAIT, NULL, NULL);

    if (numbytes > 0)
    {
      printf("listener2: got packet %d bytes\n", numbytes);

      dest1.sin_port = tcph2->dest;
      dest1.sin_addr.s_addr = iph2->daddr;
      memcpy(send1, recv2, numbytes);

      if (numbytes = (sendto(sock1, send1, numbytes, 0, (struct sockaddr *)&dest1, sizeof(struct sockaddr_in))) < 0)
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
