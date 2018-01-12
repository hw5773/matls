/** 
 * @file middlebox.h
 * @author Hyunwoo Lee
 * @date 12 Jan 2018
 * @brief This file is to define the states and the interfaces for the middlebox
 */

#ifndef __MIDDLEBOX_H__
#define __MIDDLEBOX_H__

/* Packet related Headers */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#define DEFAULT_IF  "eth0"
#define BUF_SIZE    2048

/**
 * @brief Packet structure
 */
struct pkt
{
  uint8_t *eh;        /**< This member contains the pointer to the datalink header */
  uint8_t *nh;        /**< This member contains the pointer to the network header */
  uint8_t *th;        /**< This member contains the pointer to the transport header */
  uint8_t *payload;   /**< This member contains the pointer to the application message */

  int el;             /**< The length of the datalink layer */
  int nl;             /**< The length of the network layer */
  int tl;             /**< The length of the transport layer */
  int pl;             /**< The length of the application layer */

  int ehl;            /**< The length of the datalink header */
  int nhl;            /**< The length of the network header */
  int thl;            /**< The length of the transport header */
  int phl;            /**< The length of the payload */
};

/**
 * @brief IP related process
 * @param buf IP packet, including transport layer and application layer
 * @param len Length of the IP packet
 * @return Error code (defined in error.h)
 */
int process_ip(uint8_t *buf, int len);

/**
 * @brief TCP related process
 * @param buf TCP segment
 * @param len Length of the TCP segment
 * @return Error code (defined in error.h)
 */
int process_tcp(uint8_t *buf, int len);

/**
* @brief UDP related process
* @param buf UDP segment
* @param len Length of the UDP segment
* @return Error code (defined in error.h)
*/
int process_udp(uint8_t *buf, int len);

/**
 * @brief Print IP address and port of the packet
 * @param ip IP address of the packet
 * @param port Port of the packet
 * @return void
 */
void print_info(int ip, int port);

#endif
