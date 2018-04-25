#ifndef __ADDR_POOL_H_
#define __ADDR_POOL_H_

#include <netinet/in.h>
#include <sys/queue.h>

/*----------------------------------------------------------------------------*/
typedef struct addr_pool *addr_pool_t;
/*----------------------------------------------------------------------------*/
/* CreateAddressPool()                                                        */
/* Create address pool for given address range.                               */
/* addr_base: the base address in network order.                              */
/* num_addr: number of addresses to use as source IP                          */
/*----------------------------------------------------------------------------*/
addr_pool_t 
create_address_pool(in_addr_t addr_base, int num_addr);
/*----------------------------------------------------------------------------*/
/* CreateAddressPoolPerCore()                                                 */
/* Create address pool only for the given core number.                        */
/* All addresses and port numbers should be in network order.                 */
/*----------------------------------------------------------------------------*/
addr_pool_t 
create_address_pool_per_core(int core, int num_queues, 
		in_addr_t saddr_base, int num_addr, in_addr_t daddr, in_port_t dport);
/*----------------------------------------------------------------------------*/
void
destroy_address_pool(addr_pool_t ap);
/*----------------------------------------------------------------------------*/
int 
fetch_address(addr_pool_t ap, int core, int num_queues, 
		const struct sockaddr_in *daddr, struct sockaddr_in *saddr);
/*----------------------------------------------------------------------------*/
int 
fetch_address_per_core(addr_pool_t ap, int core, int num_queues, 
		    const struct sockaddr_in *daddr, struct sockaddr_in *saddr);
/*----------------------------------------------------------------------------*/
int 
free_address(addr_pool_t ap, const struct sockaddr_in *addr);
/*----------------------------------------------------------------------------*/

#endif /* __ADDR_POOL_H_ */
