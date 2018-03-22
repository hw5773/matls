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

  struct iphdr *iph = (struct iphdr *) (recv);

  memset(&if_ip, 0, sizeof(struct ifreq));

  if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
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

  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
  {
    perror("Error while setting socket options");
    exit(EXIT_FAILURE);
  }

  if (init_repo_table() < 0)
  {
    perror("Error while initializeing pair entry repository table");
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    MB_LOG("listener: Waiting to recvfrom...");
    numbytes = recvfrom(sock, recv, BUF_SIZE, 0, NULL, NULL);
    MB_LOG1d("listener: got packet", numbytes);

    // Check whether the transport layer protocol for the packet
    MB_LOG("This is TCP segment");
    struct tcphdr *tcph = (struct tcphdr *)(recv + iph->ihl * 4);
    len = ntohs(iph->tot_len);

    if (check_checksum(recv, len) < 0) continue;
    struct pair_entry *tmp = (struct pair_entry *)malloc(sizeof(struct pair_entry));
    if (parse_entry(tmp, recv, len) < 0) continue;

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
  }

done:
  close(sock);
  return ret;
}
