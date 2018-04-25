#include <sys/queue.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <string.h>

#include "include/mssl.h"
#include "include/tcp_stream.h"
#include "include/eventpoll.h"
#include "include/tcp_in.h"
#include "include/pipe.h"
#include "include/tcp_rb.h"
#include "include/config.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define SPIN_BEFORE_SLEEP FALSE
#define SPIN_THRESH 10000000

/*----------------------------------------------------------------------------*/
char *event_str[] = {"NONE", "IN", "PRI", "OUT", "ERR", "HUP", "RDHUP"};
/*----------------------------------------------------------------------------*/
char * 
event_to_string(uint32_t event)
{
	switch (event) {
		case MOS_EPOLLNONE:
			return event_str[0];
			break;
		case MOS_EPOLLIN:
			return event_str[1];
			break;
		case MOS_EPOLLPRI:
			return event_str[2];
			break;
		case MOS_EPOLLOUT:
			return event_str[3];
			break;
		case MOS_EPOLLERR:
			return event_str[4];
			break;
		case MOS_EPOLLHUP:
			return event_str[5];
			break;
		case MOS_EPOLLRDHUP:
			return event_str[6];
			break;
		default:
			assert(0);
	}
	
	assert(0);
	return NULL;
}
/*----------------------------------------------------------------------------*/
struct event_queue *
create_event_queue(int size)
{
	struct event_queue *eq;

	eq = (struct event_queue *)calloc(1, sizeof(struct event_queue));
	if (!eq)
		return NULL;

	eq->start = 0;
	eq->end = 0;
	eq->size = size;
	eq->events = (struct mssl_epoll_event_int *)
			calloc(size, sizeof(struct mssl_epoll_event_int));
	if (!eq->events) {
		free(eq);
		return NULL;
	}
	eq->num_events = 0;

	return eq;
}
/*----------------------------------------------------------------------------*/
void 
destroy_event_queue(struct event_queue *eq)
{
	if (eq->events)
		free(eq->events);

	free(eq);
}
/*----------------------------------------------------------------------------*/
int 
mssl_epoll_create(mctx_t mctx, int size)
{
	mssl_manager_t mssl = g_mssl[mctx->cpu];
	struct mssl_epoll *ep;
	socket_map_t epsocket;

	if (size <= 0) {
		errno = EINVAL;
		return -1;
	}

	epsocket = allocate_socket(mctx, MOS_SOCK_EPOLL);
	if (!epsocket) {
		errno = ENFILE;
		return -1;
	}

	ep = (struct mssl_epoll *)calloc(1, sizeof(struct mssl_epoll));
	if (!ep) {
		free_socket(mctx, epsocket->id, MOS_SOCK_EPOLL);
		return -1;
	}

	/* create event queues */
	ep->usr_queue = create_event_queue(size);
	if (!ep->usr_queue) {
		free_socket(mctx, epsocket->id, FALSE);
		free(ep);
		return -1;
	}

	ep->usr_shadow_queue = create_event_queue(size);
	if (!ep->usr_shadow_queue) {
		destroy_event_queue(ep->usr_queue);
		free_socket(mctx, epsocket->id, FALSE);
		free(ep);
		return -1;
	}

	ep->mssl_queue = create_event_queue(size);
	if (!ep->mssl_queue) {
		destroy_event_queue(ep->usr_shadow_queue);
		destroy_event_queue(ep->usr_queue);
		free_socket(mctx, epsocket->id, FALSE);
		free(ep);
		return -1;
	}

	mssl->ep = ep;
	epsocket->ep = ep;

	if (pthread_mutex_init(&ep->epoll_lock, NULL)) {
		destroy_event_queue(ep->mssl_queue);
		destroy_event_queue(ep->usr_shadow_queue);
		destroy_event_queue(ep->usr_queue);
		free_socket(mctx, epsocket->id, FALSE);
		free(ep);
		return -1;
	}

	if (pthread_cond_init(&ep->epoll_cond, NULL)) {
		destroy_event_queue(ep->mssl_queue);
		destroy_event_queue(ep->usr_shadow_queue);
		destroy_event_queue(ep->usr_queue);
		free_socket(mctx, epsocket->id, FALSE);
		free(ep);
		return -1;
	}

	return epsocket->id;
}
/*----------------------------------------------------------------------------*/
int 
close_epoll_socket(mctx_t mctx, int epid)
{
	mssl_manager_t mssl;
	struct mssl_epoll *ep;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		return -1;
	}

	ep = mssl->smap[epid].ep;
	if (!ep) {
		errno = EINVAL;
		return -1;
	}

	destroy_event_queue(ep->usr_queue);
	destroy_event_queue(ep->usr_shadow_queue);
	destroy_event_queue(ep->mssl_queue);

	pthread_mutex_lock(&ep->epoll_lock);
	mssl->ep = NULL;
	mssl->smap[epid].ep = NULL;
	pthread_cond_signal(&ep->epoll_cond);
	pthread_mutex_unlock(&ep->epoll_lock);

	pthread_cond_destroy(&ep->epoll_cond);
	pthread_mutex_destroy(&ep->epoll_lock);
	free(ep);

	return 0;
}
/*----------------------------------------------------------------------------*/
static int 
raise_pending_stream_events(mssl_manager_t mssl, 
		struct mssl_epoll *ep, socket_map_t socket)
{
	tcp_stream *stream = socket->stream;

	if (!stream)
		return -1;
	if (stream->state < TCP_ST_ESTABLISHED)
		return -1;

	/* if there are payloads already read before epoll registration */
	/* generate read event */
	if (socket->epoll & MOS_EPOLLIN) {
		struct tcp_recv_vars *rcvvar = stream->rcvvar;
		if (rcvvar->rcvbuf && tcprb_cflen(rcvvar->rcvbuf) > 0) {
			add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLIN);
		} else if (stream->state == TCP_ST_CLOSE_WAIT) {
			add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLIN);
		}
	}

	/* same thing to the write event */
	if (socket->epoll & MOS_EPOLLOUT) {
		struct tcp_send_vars *sndvar = stream->sndvar;
		if (!sndvar->sndbuf || 
				(sndvar->sndbuf && sndvar->sndbuf->len < sndvar->snd_wnd)) {
			if (!(socket->events & MOS_EPOLLOUT)) {
				add_epoll_event(ep, USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLOUT);
			}
		}
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_epoll_ctl(mctx_t mctx, int epid, 
		int op, int sockid, struct mssl_epoll_event *event)
{
	mssl_manager_t mssl;
	struct mssl_epoll *ep;
	socket_map_t socket;
	uint32_t events;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		return -1;
	}

	if (epid < 0 || epid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[epid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[epid].socktype != MOS_SOCK_EPOLL) {
		errno = EINVAL;
		return -1;
	}

	ep = mssl->smap[epid].ep;
	if (!ep || (!event && op != MOS_EPOLL_CTL_DEL)) {
		errno = EINVAL;
		return -1;
	}
	socket = &mssl->smap[sockid];

	if (op == MOS_EPOLL_CTL_ADD) {
		if (socket->epoll) {
			errno = EEXIST;
			return -1;
		}

		/* EPOLLERR and EPOLLHUP are registered as default */
		events = event->events;
		events |= (MOS_EPOLLERR | MOS_EPOLLHUP);
		socket->ep_data = event->data;
		socket->epoll = events;

		
		if (socket->socktype == MOS_SOCK_STREAM) {
			raise_pending_stream_events(mssl, ep, socket);
		} else if (socket->socktype == MOS_SOCK_PIPE) {
			raise_pending_pipe_events(mctx, epid, sockid);
		}

	} else if (op == MOS_EPOLL_CTL_MOD) {
		if (!socket->epoll) {
			pthread_mutex_unlock(&ep->epoll_lock);
			errno = ENOENT;
			return -1;
		}

		events = event->events;
		events |= (MOS_EPOLLERR | MOS_EPOLLHUP);
		socket->ep_data = event->data;
		socket->epoll = events;

		if (socket->socktype == MOS_SOCK_STREAM) {
			raise_pending_stream_events(mssl, ep, socket);
		} else if (socket->socktype == MOS_SOCK_PIPE) {
			raise_pending_pipe_events(mctx, epid, sockid);
		}

	} else if (op == MOS_EPOLL_CTL_DEL) {
		if (!socket->epoll) {
			errno = ENOENT;
			return -1;
		}

		socket->epoll = MOS_EPOLLNONE;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_epoll_wait(mctx_t mctx, int epid, 
		struct mssl_epoll_event *events, int maxevents, int timeout)
{
  MA_LOG("mssl_epoll_wait start");
	mssl_manager_t mssl;
	struct mssl_epoll *ep;
	struct event_queue *eq;
	struct event_queue *eq_shadow;
	socket_map_t event_socket;
	int validity;
	int i, cnt, ret;
	int num_events;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		return -1;
	}

	if (epid < 0 || epid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[epid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[epid].socktype != MOS_SOCK_EPOLL) {
		errno = EINVAL;
		return -1;
	}

	ep = mssl->smap[epid].ep;
	if (!ep || !events || maxevents <= 0) {
		errno = EINVAL;
		return -1;
	}

	ep->stat.calls++;

  MA_LOG("spin before sleep");
#if SPIN_BEFORE_SLEEP
  MA_LOG("spin sleep");
	int spin = 0;
	while (ep->num_events == 0 && spin < SPIN_THRESH) {
		spin++;
	}
#endif /* SPIN_BEFORE_SLEEP */

  MA_LOG("mutex lock");
	if (pthread_mutex_lock(&ep->epoll_lock)) {
		if (errno == EDEADLK)
			perror("mssl_epoll_wait: epoll_lock blocked\n");
		assert(0);
	}
  MA_LOG("mutex lock release");

wait:
	eq = ep->usr_queue;
	eq_shadow = ep->usr_shadow_queue;

	/* wait until event occurs */
	while (eq->num_events == 0 && eq_shadow->num_events == 0 && timeout != 0) {
    MA_LOG("wait until event occurs");

#if INTR_SLEEPING_mssl
		/* signal to mssl thread if it is sleeping */
		if (mssl->wakeup_flag && mssl->is_sleeping) {
			pthread_kill(mssl->ctx->thread, SIGUSR1);
		}
#endif
		ep->stat.waits++;
		ep->waiting = TRUE;
		if (timeout > 0) {
			struct timespec deadline;

			clock_gettime(CLOCK_REALTIME, &deadline);
			if (timeout >= 1000) {
				int sec;
				sec = timeout / 1000;
				deadline.tv_sec += sec;
				timeout -= sec * 1000;
			}

			deadline.tv_nsec += timeout * 1000000;

			if (deadline.tv_nsec >= 1000000000) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000;
			}

			//deadline.tv_sec = mssl->cur_tv.tv_sec;
			//deadline.tv_nsec = (mssl->cur_tv.tv_usec + timeout * 1000) * 1000;
			ret = pthread_cond_timedwait(&ep->epoll_cond, 
					&ep->epoll_lock, &deadline);
			if (ret && ret != ETIMEDOUT) {
				/* errno set by pthread_cond_timedwait() */
				pthread_mutex_unlock(&ep->epoll_lock);
				return -1;
			}
			timeout = 0;
		} else if (timeout < 0) {
			ret = pthread_cond_wait(&ep->epoll_cond, &ep->epoll_lock);
			if (ret) {
				/* errno set by pthread_cond_wait() */
				pthread_mutex_unlock(&ep->epoll_lock);
				return -1;
			}
		}
		ep->waiting = FALSE;

		if (mssl->ctx->done || mssl->ctx->exit || mssl->ctx->interrupt) {
			mssl->ctx->interrupt = FALSE;
			//ret = pthread_cond_signal(&ep->epoll_cond);
			pthread_mutex_unlock(&ep->epoll_lock);
			errno = EINTR;
			return -1;
		}
	
	}
	
	/* fetch events from the user event queue */
	cnt = 0;
	num_events = eq->num_events;
	for (i = 0; i < num_events && cnt < maxevents; i++) {
		event_socket = &mssl->smap[eq->events[eq->start].sockid];
		validity = TRUE;
		if (event_socket->socktype == MOS_SOCK_UNUSED)
			validity = FALSE;
		if (!(event_socket->epoll & eq->events[eq->start].ev.events))
			validity = FALSE;
		if (!(event_socket->events & eq->events[eq->start].ev.events))
			validity = FALSE;

		if (validity) {
			events[cnt++] = eq->events[eq->start].ev;
			assert(eq->events[eq->start].sockid >= 0);

			ep->stat.handled++;
		} else {
			ep->stat.invalidated++;
		}
		event_socket->events &= (~eq->events[eq->start].ev.events);

		eq->start++;
		eq->num_events--;
		if (eq->start >= eq->size) {
			eq->start = 0;
		}
	}

	/* fetch eventes from user shadow event queue */
	eq = ep->usr_shadow_queue;
	num_events = eq->num_events;
	for (i = 0; i < num_events && cnt < maxevents; i++) {
		event_socket = &mssl->smap[eq->events[eq->start].sockid];
		validity = TRUE;
		if (event_socket->socktype == MOS_SOCK_UNUSED)
			validity = FALSE;
		if (!(event_socket->epoll & eq->events[eq->start].ev.events))
			validity = FALSE;
		if (!(event_socket->events & eq->events[eq->start].ev.events))
			validity = FALSE;

		if (validity) {
			events[cnt++] = eq->events[eq->start].ev;
			assert(eq->events[eq->start].sockid >= 0);

			ep->stat.handled++;
		} else {
			ep->stat.invalidated++;
		}
		event_socket->events &= (~eq->events[eq->start].ev.events);

		eq->start++;
		eq->num_events--;
		if (eq->start >= eq->size) {
			eq->start = 0;
		}
	}

	if (cnt == 0 && timeout != 0)
		goto wait;

	pthread_mutex_unlock(&ep->epoll_lock);

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
add_epoll_event(struct mssl_epoll *ep, 
		int queue_type, socket_map_t socket, uint32_t event)
{
#ifdef DBGMSG
	__PREPARE_DBGLOGGING();
#endif
	struct event_queue *eq;
	int index;

	if (!ep || !socket || !event)
		return -1;
	
	ep->stat.issued++;

	if (socket->events & event) {
		return 0;
	}

	if (queue_type == MOS_EVENT_QUEUE) {
		eq = ep->mssl_queue;
	} else if (queue_type == USR_EVENT_QUEUE) {
		eq = ep->usr_queue;
		pthread_mutex_lock(&ep->epoll_lock);
	} else if (queue_type == USR_SHADOW_EVENT_QUEUE) {
		eq = ep->usr_shadow_queue;
	} else {
		return -1;
	}

	if (eq->num_events >= eq->size) {
		if (queue_type == USR_EVENT_QUEUE)
			pthread_mutex_unlock(&ep->epoll_lock);
		return -1;
	}

	index = eq->end++;

	socket->events |= event;
	eq->events[index].sockid = socket->id;
	eq->events[index].ev.events = event;
	eq->events[index].ev.data = socket->ep_data;

	if (eq->end >= eq->size) {
		eq->end = 0;
	}
	eq->num_events++;

	if (queue_type == USR_EVENT_QUEUE)
		pthread_mutex_unlock(&ep->epoll_lock);

	ep->stat.registered++;

	return 0;
}
