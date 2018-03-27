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

#endif
