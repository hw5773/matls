#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <string.h>

#include "include/mssl.h"
#include "include/icmp.h"
#include "include/eth_out.h"
#include "include/ip_in.h"
#include "include/ip_out.h"
#include "include/arp.h"
#include "include/timer.h"
#include "include/config.h"

#define IP_NEXT_PTR(iph) ((uint8_t *)iph + (iph->ihl << 2))
void 
dump_icmp_packet(struct icmphdr *icmph, uint32_t saddr, uint32_t daddr);

/*----------------------------------------------------------------------------*/

/*
struct icmphdr
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
    uint16_t icmp_id;
    uint16_t icmp_sequence;
};
*/

/*----------------------------------------------------------------------------*/
static uint16_t
icmp_checksum(uint16_t *icmph, int len)
{
    assert(len >= 0);

    uint16_t ret = 0;
    uint32_t sum = 0;
    uint16_t odd_byte;
    
    while (len > 1) {
        sum += *icmph++;
        len -= 2;
    }
    
    if (len == 1) {
        *(uint8_t*)(&odd_byte) = * (uint8_t*)icmph;
        sum += odd_byte;
    }
    
    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret =  ~sum;
    
    return ret; 
}
/*----------------------------------------------------------------------------*/
static uint8_t*
icmp_output(struct mssl_manager *mssl, struct pkt_ctx *pctx, uint32_t saddr, uint32_t daddr,
        uint8_t icmp_type, uint8_t icmp_code, uint16_t icmp_id, uint16_t icmp_seq,
        uint8_t *icmpd, uint16_t len)
{
    struct iphdr *iph;
    int32_t nif;
    uint8_t *haddr;
    struct icmphdr *icmph;
    uint32_t pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + len;
    struct timeval cur_ts = {0};
    uint32_t ts;
    
    /* Get hardware interface to forward the packet*/
    nif = GetOutputInterface(daddr);
    if (nif < 0)
        return (uint8_t *) ERROR;

    /* Get next hop MAC address */
    haddr = get_destination_hw_addr(daddr);
    if (!haddr) {
        uint8_t *da = (uint8_t *)&daddr;
	/* ARP requests will not be created if it's a standalone middlebox */
	if (!pctx->forward)        
		request_arp(mssl, daddr, nif, mssl->cur_ts);
        haddr = get_destination_hw_addr(daddr);
    }
   
    /* Check if we have valid next hop address */
    if (!haddr)
	    return (uint8_t *) ERROR;
    
    /* Set up timestamp for ethernet_output */
    gettimeofday(&cur_ts, NULL);
    ts = TIMEVAL_TO_TS(&cur_ts);
    
    /* Allocate a buffer */
    iph = (struct iphdr *)ethernet_output(mssl, pctx, ETH_P_IP, nif, haddr, pktlen, ts);
    if (!iph)
	    return (uint8_t *) ERROR;
    
    /* Fill in the ip header */
    iph->ihl = IP_HEADER_LEN >> 2;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pktlen);
    iph->id = htons(0);
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = saddr;
    iph->daddr = daddr;
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    
    icmph = (struct icmphdr *) IP_NEXT_PTR(iph);
    
    /* Fill in the icmp header */
    icmph->icmp_type = icmp_type;
    icmph->icmp_code = icmp_code;
    icmph->icmp_checksum = 0;
    ICMP_ECHO_SET_ID(icmph, htons(icmp_id));
    ICMP_ECHO_SET_SEQ(icmph, htons(icmp_seq));
    
    /* Fill in the icmp data */
    if(len > 0)
        memcpy((void *) (icmph + 1), icmpd, len);

    /* Calculate ICMP Checksum with header and data */
    icmph->icmp_checksum = 
                       icmp_checksum((uint16_t *)icmph, sizeof(struct icmphdr) + len);

#if DBGMSG
    dump_icmp_packet(icmph, saddr, daddr);
#endif
    return (uint8_t *)(iph + 1);
}
/*----------------------------------------------------------------------------*/
void
request_icmp(mssl_manager_t mssl, struct pkt_ctx *pctx, uint32_t saddr, uint32_t daddr,
        uint16_t icmp_id, uint16_t icmp_sequence,
        uint8_t *icmpd, uint16_t len)
{
    /* send icmp request with given parameters */
    icmp_output(mssl, pctx, saddr, daddr, ICMP_ECHO, 0, ntohs(icmp_id), ntohs(icmp_sequence),
               icmpd, len);
}
/*----------------------------------------------------------------------------*/
static int 
process_icmp_echo_request(mssl_manager_t mssl, struct pkt_ctx *pctx, struct icmphdr *icmph)
{
    int ret = 0;

    /* Check correctness of ICMP checksum and send ICMP echo reply */
    if (icmp_checksum((uint16_t *) icmph, pctx->p.ip_len - (pctx->p.iph->ihl << 2) )) 
        ret = ERROR;
    else
        icmp_output(mssl, pctx, pctx->p.iph->daddr, pctx->p.iph->saddr, ICMP_ECHOREPLY, 0, 
                   ntohs(ICMP_ECHO_GET_ID(icmph)), ntohs(ICMP_ECHO_GET_SEQ(icmph)), (uint8_t *) (icmph + 1),
                   (uint16_t) (pctx->p.ip_len - (pctx->p.iph->ihl << 2) - sizeof(struct icmphdr)) );

    return ret;
}
/*----------------------------------------------------------------------------*/
static int
process_icmp_echo_reply(mssl_manager_t mssl, struct pkt_ctx *pctx, struct icmphdr *icmph)
{ 

    /* XXX We can allow sending ping request from mOS app. IMHO, it's bad */

#if 0
    uint8_t type, code;
    uint16_t seq, id;  

    /* Extract ICMP field from packet */
    type = icmph->icmp_type;
    code = icmph->icmp_code;
    seq  = ntohs(ICMP_ECHO_GET_SEQ(icmph));
    id   = ntohs(ICMP_ECHO_GET_ID(icmph));
#endif
    return 0;
}
/*----------------------------------------------------------------------------*/
int 
process_icmp_packet(mssl_manager_t mssl, struct pkt_ctx *pctx)
{
    struct icmphdr *icmph = (struct icmphdr *) IP_NEXT_PTR(pctx->p.iph);
    int i;
    int to_me = FALSE;

    /* process the icmp messages destined to me */
    for (i = 0; i < g_config.mos->netdev_table->num; i++) {
        if (pctx->p.iph->daddr == g_config.mos->netdev_table->ent[i]->ip_addr) {
            to_me = TRUE;
        }
    }

    if (!to_me)
        return FALSE;
    
    switch (icmph->icmp_type)
    {
        case ICMP_ECHO:
            process_icmp_echo_request(mssl, pctx, icmph);
            break;
            
        case ICMP_ECHOREPLY:
            process_icmp_echo_reply(mssl, pctx, icmph);
            break;

        case ICMP_DEST_UNREACH:
            break;

        case ICMP_TIME_EXCEEDED:
            break;

        default:
            break;
    }
    
    return TRUE;
}
/*----------------------------------------------------------------------------*/
void 
dump_icmp_packet(struct icmphdr *icmph, uint32_t saddr, uint32_t daddr)
{
    uint8_t *t;

    fprintf(stderr, "ICMP header: \n");
    fprintf(stderr, "Type: %d, "
            "Code: %d, ID: %d, Sequence: %d\n", 
            icmph->icmp_type, icmph->icmp_code,
            ICMP_ECHO_GET_ID(icmph), ICMP_ECHO_GET_SEQ(icmph));

    t = (uint8_t *)&saddr;
    fprintf(stderr, "Sender IP: %u.%u.%u.%u\n",
            t[0], t[1], t[2], t[3]);

    t = (uint8_t *)&daddr;
    fprintf(stderr, "Target IP: %u.%u.%u.%u\n",
            t[0], t[1], t[2], t[3]);
}
/*----------------------------------------------------------------------------*/
#undef IP_NEXT_PTR
