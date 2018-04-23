#ifndef __EVENTPOLL_H_
#define __EVENTPOLL_H_

#include "mssl_api.h"
#include "mssl_epoll.h"

/*----------------------------------------------------------------------------*/
struct mssl_epoll_stat
{
	uint64_t calls;
	uint64_t waits;
	uint64_t wakes;

	uint64_t issued;
	uint64_t registered;
	uint64_t invalidated;
	uint64_t handled;
};
/*----------------------------------------------------------------------------*/
struct mssl_epoll_event_int
{
	struct mssl_epoll_event ev;
	int sockid;
};
/*----------------------------------------------------------------------------*/
enum event_queue_type
{
	USR_EVENT_QUEUE = 0, 
	USR_SHADOW_EVENT_QUEUE = 1, 
	MOS_EVENT_QUEUE = 2
};
/*----------------------------------------------------------------------------*/
struct event_queue
{
	struct mssl_epoll_event_int *events;
	int start;			// starting index
	int end;			// ending index
	
	int size;			// max size
	int num_events;		// number of events
};
/*----------------------------------------------------------------------------*/
struct mssl_epoll
{
	struct event_queue *usr_queue;
	struct event_queue *usr_shadow_queue;
	struct event_queue *mssl_queue;

	uint8_t waiting;
	struct mssl_epoll_stat stat;
	
	pthread_cond_t epoll_cond;
	pthread_mutex_t epoll_lock;
};
/*----------------------------------------------------------------------------*/

int close_epoll_socket(mctx_t mctx, int epid);

struct event_queue *create_event_queue(int size);

void destroy_event_queue(struct event_queue *eq);

#endif /* __EVENTPOLL_H_ */
