#ifndef __MOS_API_H__
#define __MOS_API_H__

#ifdef DARWIN
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#else
#include <linux/tcp.h>
#include <linux/if_ether.h>
#endif /* DARWIN */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stddef.h>
#include "mssl_epoll.h"
#include <stdbool.h>

#ifndef __MSSL_MANAGER__
#define __MSSL_MSNAGER__
typedef struct mssl_manager *mssl_manager_t;
#endif

#endif /* __MSSL_API_H__ */
