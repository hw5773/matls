#include <sys/queue.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#ifdef DARWIN
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#endif

#include "include/mssl.h"
#include "include/mssl_api.h"
#include "include/tcp_in.h"
#include "include/tcp_stream.h"
#include "include/tcp_out.h"
#include "include/ip_out.h"
#include "include/eventpoll.h"
#include "include/pipe.h"
#include "include/fhash.h"
#include "include/addr_pool.h"
#include "include/util.h"
#include "include/config.h"
#include "include/eventpoll.h"
#include "include/mos_api.h"
#include "include/tcp_rb.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/*----------------------------------------------------------------------------*/
/** Stop monitoring the socket! (function prototype)
 * @param [in] mctx: mssl context
 * @param [in] sock: monitoring stream socket id
 * @param [in] side: side of monitoring (client side, server side or both)
 *
 * This function is now DEPRECATED and is only used within mOS core...
 */
int
mssl_cb_stop(mctx_t mctx, int sock, int side);
/*----------------------------------------------------------------------------*/
/** Reset the connection (send RST packets to both sides)
 *  (We need to decide the API for this.)
 */
//int
//mssl_cb_reset(mctx_t mctx, int sock, int side);
/*----------------------------------------------------------------------------*/
inline mssl_manager_t 
get_mssl_manager(mctx_t mctx)
{
	if (!mctx) {
		errno = EACCES;
		return NULL;
	}

	if (mctx->cpu < 0 || mctx->cpu >= num_cpus) {
		errno = EINVAL;
		return NULL;
	}

	if (!g_mssl[mctx->cpu] || g_mssl[mctx->cpu]->ctx->done || g_mssl[mctx->cpu]->ctx->exit) {
		errno = EPERM;
		return NULL;
	}

	return g_mssl[mctx->cpu];
}
/*----------------------------------------------------------------------------*/
static inline int 
get_socket_error(socket_map_t socket, void *optval, socklen_t *optlen)
{
	tcp_stream *cur_stream;

	if (!socket->stream) {
		errno = EBADF;
		return -1;
	}

	cur_stream = socket->stream;
	if (cur_stream->state == TCP_ST_CLOSED_RSVD) {
		if (cur_stream->close_reason == TCP_TIMEDOUT || 
				cur_stream->close_reason == TCP_CONN_FAIL || 
				cur_stream->close_reason == TCP_CONN_LOST) {
			*(int *)optval = ETIMEDOUT;
			*optlen = sizeof(int);

			return 0;
		}
	}

	if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_CLOSED_RSVD) { 
		if (cur_stream->close_reason == TCP_RESET) {
			*(int *)optval = ECONNRESET;
			*optlen = sizeof(int);

			return 0;
		}
	}

	if (cur_stream->state == TCP_ST_SYN_SENT &&
	    errno == EINPROGRESS) {
		*(int *)optval = errno;
		*optlen = sizeof(int);
		
		return -1;
	}

	/*
	 * `base case`: If socket sees no so_error, then
	 * this also means close_reason will always be
	 * TCP_NOT_CLOSED. 
	 */
	if (cur_stream->close_reason == TCP_NOT_CLOSED) {
		*(int *)optval = 0;
		*optlen = sizeof(int);
		
		return 0;
	}
	
	errno = ENOSYS;
	return -1;
}
/*----------------------------------------------------------------------------*/
int
mssl_getsockname(mctx_t mctx, int sockid, struct sockaddr *addr,
		 socklen_t *addrlen)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}
	
	socket = &mssl->smap[sockid];
	if (socket->socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (*addrlen <= 0) {
		errno = EINVAL;
		return -1;
	}
	
	if (socket->socktype != MOS_SOCK_STREAM_LISTEN && 
	    socket->socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	*(struct sockaddr_in *)addr = socket->saddr;
        *addrlen = sizeof(socket->saddr);

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_getsockopt(mctx_t mctx, int sockid, int level, 
		int optname, void *optval, socklen_t *optlen)
{
	mssl_manager_t mssl;
	socket_map_t socket;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	switch (level) {
	case SOL_SOCKET:
		socket = &mssl->smap[sockid];
		if (socket->socktype == MOS_SOCK_UNUSED) {
			errno = EBADF;
			return -1;
		}
		
		if (socket->socktype != MOS_SOCK_STREAM_LISTEN && 
		    socket->socktype != MOS_SOCK_STREAM) {
			errno = ENOTSOCK;
			return -1;
		}
		
		if (optname == SO_ERROR) {
			if (socket->socktype == MOS_SOCK_STREAM) {
				return get_socket_error(socket, optval, optlen);
			}
		}
		break;
	case SOL_MONSOCKET:
		/* check if the calling thread is in MOS context */
		if (mssl->ctx->thread != pthread_self()) {
			errno = EPERM;
			return -1;
		}
		/*
		 * All options will only work for active 
		 * monitor stream sockets
		 */
		socket = &mssl->msmap[sockid];
		if (socket->socktype != MOS_SOCK_MONITOR_STREAM_ACTIVE) {
			errno = ENOTSOCK;
			return -1;
		}

		switch (optname) {
		case MOS_FRAGINFO_CLIBUF:
			return get_frag_info(socket, MOS_SIDE_CLI, optval, optlen);
		case MOS_FRAGINFO_SVRBUF:
			return get_frag_info(socket, MOS_SIDE_SVR, optval, optlen);
		case MOS_INFO_CLIBUF:
			return get_buf_info(socket, MOS_SIDE_CLI, optval, optlen);
		case MOS_INFO_SVRBUF:
			return get_buf_info(socket, MOS_SIDE_SVR, optval, optlen);
		case MOS_TCP_STATE_CLI:
			return get_tcp_state(socket->monitor_stream->stream, MOS_SIDE_CLI,
							   optval, optlen);
		case MOS_TCP_STATE_SVR:
			return get_tcp_state(socket->monitor_stream->stream, MOS_SIDE_SVR,
							   optval, optlen);
		case MOS_TIMESTAMP:
			return get_last_timestamp(socket->monitor_stream->stream,
						(uint32_t *)optval, 
						optlen);
		default: 
		  assert(0);
		}
		break;
	}
	errno = ENOSYS;
	return -1;
}
/*----------------------------------------------------------------------------*/
int 
mssl_setsockopt(mctx_t mctx, int sockid, int level, 
		int optname, const void *optval, socklen_t optlen)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcprb_t *rb;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	switch (level) {
	case SOL_SOCKET:
		socket = &mssl->smap[sockid];
		if (socket->socktype == MOS_SOCK_UNUSED) {
			errno = EBADF;
			return -1;
		}

		if (socket->socktype != MOS_SOCK_STREAM_LISTEN && 
		    socket->socktype != MOS_SOCK_STREAM) {
			errno = ENOTSOCK;
			return -1;
		}
		break;
	case SOL_MONSOCKET:
		socket = &mssl->msmap[sockid];
		/* 
		 * checking of calling thread to be in MOS context is
		 * disabled since both optnames can be called from
		 * `application' context (on passive sockets)
		 */
		/* 
		 * if (mssl->ctx->thread != pthread_self())
		 * return -1;
		 */
		
		switch (optname) {
		case MOS_CLIOVERLAP:
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_CLI) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
			socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (rb == NULL) {
				errno = EFAULT;
				return -1;
			}
			if (tcprb_setpolicy(rb, *(uint8_t *)optval) < 0) {
				errno = EINVAL;
				return -1;
			} else
				return 0;
			break;
		case MOS_SVROVERLAP:
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_SVR) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
			socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (rb == NULL) {
				errno = EFAULT;
				return -1;
			}
			if (tcprb_setpolicy(rb, *(uint8_t *)optval) < 0) {
				errno = EINVAL;
				return -1;
			} else
				return 0;
			break;
		case MOS_CLIBUF:
#if 0
			if (socket->socktype != MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				errno = EBADF;
				return -1;
			}
#endif
#ifdef DISABLE_DYN_RESIZE
			if (*(int *)optval != 0)
				return -1;
			if (socket->socktype == MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				rb = (socket->monitor_stream->stream->side == MOS_SIDE_CLI) ?
					socket->monitor_stream->stream->rcvvar->rcvbuf :
					socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
				if (rb) {
					tcprb_resize_meta(rb, 0);
					tcprb_resize(rb, 0);
				}
			}
			return disable_buf(socket, MOS_SIDE_CLI);
#else
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_CLI) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
				socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (tcprb_resize_meta(rb, *(int *)optval) < 0)
				return -1;
			return tcprb_resize(rb,
					(((int)rb->metalen - 1) / UNITBUFSIZE + 1) * UNITBUFSIZE);
#endif
		case MOS_SVRBUF:
#if 0
			if (socket->socktype != MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				errno = EBADF;
				return -1;
			}
#endif
#ifdef DISABLE_DYN_RESIZE
			if (*(int *)optval != 0)
				return -1;
			if (socket->socktype == MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				rb = (socket->monitor_stream->stream->side == MOS_SIDE_SVR) ?
					socket->monitor_stream->stream->rcvvar->rcvbuf :
					socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
				if (rb) {
					tcprb_resize_meta(rb, 0);
					tcprb_resize(rb, 0);
				}
			}
			return disable_buf(socket, MOS_SIDE_SVR);
#else
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_SVR) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
				socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (tcprb_resize_meta(rb, *(int *)optval) < 0)
				return -1;
			return tcprb_resize(rb,
					(((int)rb->metalen - 1) / UNITBUFSIZE + 1) * UNITBUFSIZE);
#endif
		case MOS_FRAG_CLIBUF:
#if 0
			if (socket->socktype != MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				errno = EBADF;
				return -1;
			}
#endif
#ifdef DISABLE_DYN_RESIZE
			if (*(int *)optval != 0)
				return -1;
			if (socket->socktype == MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				rb = (socket->monitor_stream->stream->side == MOS_SIDE_CLI) ?
					socket->monitor_stream->stream->rcvvar->rcvbuf :
					socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
				if (rb)
					tcprb_resize(rb, 0);
			}
			return 0;
#else
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_CLI) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
				socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (rb->len == 0)
				return tcprb_resize_meta(rb, *(int *)optval);
			else
				return -1;
#endif
		case MOS_FRAG_SVRBUF:
#if 0
			if (socket->socktype != MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				errno = EBADF;
				return -1;
			}
#endif
#ifdef DISABLE_DYN_RESIZE
			if (*(int *)optval != 0)
				return -1;
			if (socket->socktype == MOS_SOCK_MONITOR_STREAM_ACTIVE) {
				rb = (socket->monitor_stream->stream->side == MOS_SIDE_SVR) ?
					socket->monitor_stream->stream->rcvvar->rcvbuf :
					socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
				if (rb)
					tcprb_resize(rb, 0);
			}
			return 0;
#else
			rb = (socket->monitor_stream->stream->side == MOS_SIDE_SVR) ?
				socket->monitor_stream->stream->rcvvar->rcvbuf :
				socket->monitor_stream->stream->pair_stream->rcvvar->rcvbuf;
			if (rb->len == 0)
				return tcprb_resize_meta(rb, *(int *)optval);
			else
				return -1;
#endif
		case MOS_SEQ_REMAP:
			break;
		case MOS_STOP_MON:
			return mssl_cb_stop(mctx, sockid, *(int *)optval);
		default: 
			assert(0);
		}
		break;
	}

	errno = ENOSYS;
	return -1;
}
/*----------------------------------------------------------------------------*/
int 
mssl_setsock_nonblock(mctx_t mctx, int sockid)
{
	mssl_manager_t mssl;
	
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	mssl->smap[sockid].opts |= mssl_NONBLOCK;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_ioctl(mctx_t mctx, int sockid, int request, void *argp)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	/* only support stream socket */
	socket = &mssl->smap[sockid];
	
	if (socket->socktype != MOS_SOCK_STREAM_LISTEN && 
		socket->socktype != MOS_SOCK_STREAM) {
		errno = EBADF;
		return -1;
	}

	if (!argp) {
		errno = EFAULT;
		return -1;
	}

	if (request == FIONREAD) {
		tcp_stream *cur_stream;
		tcprb_t *rbuf;

		cur_stream = socket->stream;
		if (!cur_stream) {
			errno = EBADF;
			return -1;
		}
		
		rbuf = cur_stream->rcvvar->rcvbuf;
		*(int *)argp = (rbuf) ? tcprb_cflen(rbuf) : 0;

	} else if (request == FIONBIO) {
		/* 
		 * sockets can only be set to blocking/non-blocking 
		 * modes during initialization
		 */
		if ((*(int *)argp))
			mssl->smap[sockid].opts |= mssl_NONBLOCK;
		else
			mssl->smap[sockid].opts &= ~mssl_NONBLOCK;
	} else {
		errno = EINVAL;
		return -1;
	}
	
	return 0;
}
/*----------------------------------------------------------------------------*/
static int 
mssl_monitor(mctx_t mctx, socket_map_t sock) 
{
	mssl_manager_t mssl;
	struct mon_listener *monitor;
	int sockid = sock->id;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->msmap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (!(mssl->msmap[sockid].socktype == MOS_SOCK_MONITOR_STREAM ||
	      mssl->msmap[sockid].socktype == MOS_SOCK_MONITOR_RAW)) {
		errno = ENOTSOCK;
		return -1;
	}

	monitor = (struct mon_listener *)calloc(1, sizeof(struct mon_listener));
	if (!monitor) {
		/* errno set from the malloc() */
		errno = ENOMEM;
		return -1;
	}

	/* create a monitor-specific event queue */
	monitor->eq = create_event_queue(g_config.mos->max_concurrency);
	if (!monitor->eq) {
		free(monitor);
		errno = ENOMEM;
		return -1;
	}

	/* set monitor-related basic parameters */
#ifndef NEWEV
	monitor->ude_id = UDE_OFFSET;
#endif
	monitor->socket = sock;
	monitor->client_buf_mgmt = monitor->server_buf_mgmt = BUFMGMT_FULL;

	/* perform both sides monitoring by default */
	monitor->client_mon = monitor->server_mon = 1;

	/* add monitor socket to the monitor list */
	TAILQ_INSERT_TAIL(&mssl->monitors, monitor, link);

	mssl->msmap[sockid].monitor_listener = monitor;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_socket(mctx_t mctx, int domain, int type, int protocol)
{
	mssl_manager_t mssl;
	socket_map_t socket;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (domain != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (type == (int)SOCK_STREAM) {
		type = MOS_SOCK_STREAM;
	} 
  else if (type == MOS_SOCK_MONITOR_STREAM ||
		   type == MOS_SOCK_MONITOR_RAW) 
  {
		/* do nothing for the time being */
	} 
  else if (type == MOS_SOCK_MATLS || type == MOS_SOCK_SPLIT_TLS)
  {
  }
  else 
  {
		/* Not supported type */
		errno = EINVAL;
		return -1;
	}

	socket = allocate_socket(mctx, type);
	if (!socket) {
		errno = ENFILE;
		return -1;
	}

	if (type == MOS_SOCK_MONITOR_STREAM || 
	    type == MOS_SOCK_MONITOR_RAW) {
		mssl_manager_t mssl = get_mssl_manager(mctx);
		if (!mssl) {
			errno = EACCES;
			return -1;
		}
		mssl_monitor(mctx, socket);
#ifdef NEWEV
		socket->monitor_listener->stree_dontcare = NULL;
		socket->monitor_listener->stree_pre_rcv = NULL;
		socket->monitor_listener->stree_post_snd = NULL;
#else
		init_evb(mssl, &socket->monitor_listener->dontcare_evb);
		init_evb(mssl, &socket->monitor_listener->pre_tcp_evb);
		init_evb(mssl, &socket->monitor_listener->post_tcp_evb);
#endif
	}

	return socket->id;
}
/*----------------------------------------------------------------------------*/
int 
mssl_bind(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen)
{
	mssl_manager_t mssl;
	struct sockaddr_in *addr_in;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}
	
	if (mssl->smap[sockid].socktype != MOS_SOCK_STREAM && 
			mssl->smap[sockid].socktype != MOS_SOCK_STREAM_LISTEN) {
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	if (mssl->smap[sockid].opts & mssl_ADDR_BIND) {
		errno = EINVAL;
		return -1;
	}

	/* we only allow bind() for AF_INET address */
	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		errno = EINVAL;
		return -1;
	}

	if (mssl->listener) {
		errno = EINVAL;
		return -1;
	}
	addr_in = (struct sockaddr_in *)addr;
	mssl->smap[sockid].saddr = *addr_in;
	mssl->smap[sockid].opts |= mssl_ADDR_BIND;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_listen(mctx_t mctx, int sockid, int backlog)
{
	mssl_manager_t mssl;
	struct tcp_listener *listener;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_STREAM) {
		mssl->smap[sockid].socktype = MOS_SOCK_STREAM_LISTEN;
	}
	
	if (mssl->smap[sockid].socktype != MOS_SOCK_STREAM_LISTEN) {
		errno = ENOTSOCK;
		return -1;
	}

	if (backlog <= 0 || backlog > g_config.mos->max_concurrency) {
		errno = EINVAL;
		return -1;
	}

	listener = (struct tcp_listener *)calloc(1, sizeof(struct tcp_listener));
	if (!listener) {
		/* errno set from the malloc() */
		errno = ENOMEM;
		return -1;
	}

	listener->sockid = sockid;
	listener->backlog = backlog;
	listener->socket = &mssl->smap[sockid];

	if (pthread_cond_init(&listener->accept_cond, NULL)) {
		perror("pthread_cond_init of ctx->accept_cond\n");
		/* errno set by pthread_cond_init() */
		free(listener);
		return -1;
	}
	
  if (pthread_mutex_init(&listener->accept_lock, NULL)) {
		perror("pthread_mutex_init of ctx->accept_lock\n");
		/* errno set by pthread_mutex_init() */
		free(listener);
		return -1;
	}

	listener->acceptq = create_stream_queue(backlog);
	if (!listener->acceptq) {
		free(listener);
		errno = ENOMEM;
		return -1;
	}
	
	mssl->smap[sockid].listener = listener;
	mssl->listener = listener;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen)
{
	mssl_manager_t mssl;
	struct tcp_listener *listener;
	socket_map_t socket;
	tcp_stream *accepted = NULL;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	/* requires listening socket */
	if (mssl->smap[sockid].socktype != MOS_SOCK_STREAM_LISTEN) {
		errno = EINVAL;
		return -1;
	}

	listener = mssl->smap[sockid].listener;

	/* dequeue from the acceptq without lock first */
	/* if nothing there, acquire lock and cond_wait */
	accepted = stream_dequeue(listener->acceptq);
	if (!accepted) {
		if (listener->socket->opts & mssl_NONBLOCK) {
			errno = EAGAIN;
			return -1;

		} else {
			pthread_mutex_lock(&listener->accept_lock);
			while ((accepted = stream_dequeue(listener->acceptq)) == NULL) {
				pthread_cond_wait(&listener->accept_cond, &listener->accept_lock);
		
				if (mssl->ctx->done || mssl->ctx->exit) {
					pthread_mutex_unlock(&listener->accept_lock);
					errno = EINTR;
					return -1;
				}
			}
			pthread_mutex_unlock(&listener->accept_lock);
		}
	}

	if (!accepted) {
	}

	if (!accepted->socket) {
		socket = allocate_socket(mctx, MOS_SOCK_STREAM);
		if (!socket) {
			/* TODO: destroy the stream */
			errno = ENFILE;
			return -1;
		}
		socket->stream = accepted;
		accepted->socket = socket;

		/* set socket addr parameters */
		socket->saddr.sin_family = AF_INET;
		socket->saddr.sin_port = accepted->dport;
		socket->saddr.sin_addr.s_addr = accepted->daddr;

		/* if monitor is enabled, complete the socket assignment */
		if (socket->stream->pair_stream != NULL)
			socket->stream->pair_stream->socket = socket;
	}

	if (!(listener->socket->epoll & MOS_EPOLLET) &&
	    !stream_queue_is_empty(listener->acceptq))
		add_epoll_event(mssl->ep, 
			      USR_SHADOW_EVENT_QUEUE,
			      listener->socket, MOS_EPOLLIN);
	

	if (addr && addrlen) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = accepted->dport;
		addr_in->sin_addr.s_addr = accepted->daddr;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return accepted->socket->id;
}
/*----------------------------------------------------------------------------*/
int 
mssl_init_rss(mctx_t mctx, in_addr_t saddr_base, int num_addr, 
		in_addr_t daddr, in_addr_t dport)
{
	mssl_manager_t mssl;
	addr_pool_t ap;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (saddr_base == INADDR_ANY) {
		int nif_out;

		/* for the INADDR_ANY, find the output interface for the destination
		   and set the saddr_base as the ip address of the output interface */
		nif_out = get_output_interface(daddr);
		if (nif_out < 0) {
			errno = EINVAL;
			return -1;
		}
		saddr_base = g_config.mos->netdev_table->ent[nif_out]->ip_addr;
	}

	ap = create_address_pool_per_core(mctx->cpu, num_cpus, 
			saddr_base, num_addr, daddr, dport);
	if (!ap) {
		errno = ENOMEM;
		return -1;
	}

	mssl->ap = ap;

	return 0;
}
/*----------------------------------------------------------------------------*/
int
eval_bpf_5tuple(struct sfbpf_program fcode,
				in_addr_t saddr, in_port_t sport,
				in_addr_t daddr, in_port_t dport) {
	uint8_t buf[TOTAL_TCP_HEADER_LEN];
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ethh = (struct ethhdr *)buf;
	ethh->h_proto = htons(ETH_P_IP);
	iph = (struct iphdr *)(ethh + 1);
	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
	iph->id = htons(0);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;
	tcph = (struct tcphdr *)(iph + 1);
	tcph->source = sport;
	tcph->dest = dport;
	
	return EVAL_BPFFILTER(fcode, (uint8_t *)iph - sizeof(struct ethhdr),
						 TOTAL_TCP_HEADER_LEN);
}
/*----------------------------------------------------------------------------*/
int 
mssl_connect(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct sockaddr_in *addr_in;
	in_addr_t dip;
	in_port_t dport;
	int is_dyn_bound = FALSE;
	int ret, nif;
	int cnt_match = 0;
	struct mon_listener *walk;
	struct sfbpf_program fcode;

	cur_stream = NULL;
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}
	
	if (mssl->smap[sockid].socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		errno = EFAULT;
		return -1;
	}

	/* we only allow bind() for AF_INET address */
	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	socket = &mssl->smap[sockid];
	if (socket->stream) {
		if (socket->stream->state >= TCP_ST_ESTABLISHED) {
			errno = EISCONN;
		} else {
			errno = EALREADY;
		}
		return -1;
	}

	addr_in = (struct sockaddr_in *)addr;
	dip = addr_in->sin_addr.s_addr;
	dport = addr_in->sin_port;

	/* address binding */
	if (socket->opts & mssl_ADDR_BIND && 
	    socket->saddr.sin_port != INPORT_ANY &&
	    socket->saddr.sin_addr.s_addr != INADDR_ANY) {
		int rss_core;

		rss_core = get_rss_cpu_core(socket->saddr.sin_addr.s_addr, dip, 
					 socket->saddr.sin_port, dport, num_queues);

		if (rss_core != mctx->cpu) {
			errno = EINVAL;
			return -1;
		}
	} else {
		if (mssl->ap) {
			ret = fetch_address_per_core(mssl->ap, 
						  mctx->cpu, num_queues, addr_in, &socket->saddr);
		} else {
			nif = get_output_interface(dip);
			if (nif < 0) {
				errno = EINVAL;
				return -1;
			}
			ret = fetch_address(ap[nif], 
					   mctx->cpu, num_queues, addr_in, &socket->saddr);
		}
		if (ret < 0) {
			errno = EAGAIN;
			return -1;
		}
		socket->opts |= mssl_ADDR_BIND;
		is_dyn_bound = TRUE;
	}

	cnt_match = 0;
	if (mssl->num_msp > 0) {		
		TAILQ_FOREACH(walk, &mssl->monitors, link) {
			fcode = walk->stream_syn_fcode;
			if (!(ISSET_BPFFILTER(fcode) &&
				  eval_bpf_5tuple(fcode, socket->saddr.sin_addr.s_addr,
								  socket->saddr.sin_port,
								  dip, dport) == 0)) {
				walk->is_stream_syn_filter_hit = 1; // set the 'filter hit' flag to 1
				cnt_match++;
			}
		}
	}

	if (mssl->num_msp > 0 && cnt_match > 0) {
		/* 150820 dhkim: XXX: embedded mode is not verified */
#if 1
/*
    cur_stream = create_client_tcp_stream(mssl, socket,
						 STREAM_TYPE(MOS_SOCK_STREAM) |
						 STREAM_TYPE(MOS_SOCK_MONITOR_STREAM_ACTIVE),
						 socket->saddr.sin_addr.s_addr, 
						 socket->saddr.sin_port, dip, dport, NULL);
*/
    cur_stream = create_client_tcp_stream(mssl, socket,
						 STREAM_TYPE(MOS_SOCK_STREAM),
						 socket->saddr.sin_addr.s_addr, 
						 socket->saddr.sin_port, dip, dport, NULL);

#else
		cur_stream = CreateDualTCPStream(mssl, socket,
						 STREAM_TYPE(MOS_SOCK_STREAM) |
						 STREAM_TYPE(MOS_SOCK_MONITOR_STREAM_ACTIVE),
						 socket->saddr.sin_addr.s_addr, 
						 socket->saddr.sin_port, dip, dport, NULL);
#endif
	}
	else
		cur_stream = create_tcp_stream(mssl, socket, STREAM_TYPE(MOS_SOCK_STREAM),
					     socket->saddr.sin_addr.s_addr,
					     socket->saddr.sin_port, dip, dport, NULL);
	if (!cur_stream) {
		errno = ENOMEM;
		return -1;
	}

	if (is_dyn_bound)
		cur_stream->is_bound_addr = TRUE;
	cur_stream->sndvar->cwnd = 1;
	cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
	cur_stream->side = MOS_SIDE_CLI;
	/* if monitor is enabled, update the pair stream side as well */
	if (cur_stream->pair_stream) {
		cur_stream->pair_stream->side = MOS_SIDE_SVR;
		/* 
		 * if buffer management is off, then disable 
		 * monitoring tcp ring of server...
		 * if there is even a single monitor asking for
		 * buffer management, enable it (that's why the
		 * need for the loop)
		 */
		cur_stream->pair_stream->buffer_mgmt = BUFMGMT_OFF;
		struct socket_map *walk;
		SOCKQ_FOREACH_START(walk, &cur_stream->msocks) {
			uint8_t bm = walk->monitor_stream->monitor_listener->server_buf_mgmt;
			if (bm > cur_stream->pair_stream->buffer_mgmt) {
				cur_stream->pair_stream->buffer_mgmt = bm;
				break;
			}
		} SOCKQ_FOREACH_END;
	}

	cur_stream->state = TCP_ST_SYN_SENT;
	cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;

	SQ_LOCK(&mssl->ctx->connect_lock);
	ret = stream_enqueue(mssl->connectq, cur_stream);
	SQ_UNLOCK(&mssl->ctx->connect_lock);
	mssl->wakeup_flag = TRUE;
	if (ret < 0) {
		SQ_LOCK(&mssl->ctx->destroyq_lock);
		stream_enqueue(mssl->destroyq, cur_stream);
		SQ_UNLOCK(&mssl->ctx->destroyq_lock);
		errno = EAGAIN;
		return -1;
	}

	/* if nonblocking socket, return EINPROGRESS */
	if (socket->opts & mssl_NONBLOCK) {
		errno = EINPROGRESS;
		return -1;

	} else {
		while (1) {
			if (!cur_stream) {
				errno = ETIMEDOUT;
				return -1;
			}
			if (cur_stream->state > TCP_ST_ESTABLISHED) {
				// TODO: how to handle this?
				errno = ENOSYS;
				return -1;
			}

			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				break;
			}
			usleep(1000);
		}
	}
	
	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int 
close_stream_socket(mctx_t mctx, int sockid)
{
	mssl_manager_t mssl;
	tcp_stream *cur_stream;
	int ret;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	cur_stream = mssl->smap[sockid].stream;
	if (!cur_stream) {
		errno = ENOTCONN;
		return -1;
	}

	if (cur_stream->closed) {
		return 0;
	}
	cur_stream->closed = TRUE;
		

	/* 141029 dhkim: Check this! */
	cur_stream->socket = NULL;

	if (cur_stream->state == TCP_ST_CLOSED_RSVD) {
		SQ_LOCK(&mssl->ctx->destroyq_lock);
		stream_enqueue(mssl->destroyq, cur_stream);
		mssl->wakeup_flag = TRUE;
		SQ_UNLOCK(&mssl->ctx->destroyq_lock);
		return 0;

	} else if (cur_stream->state == TCP_ST_SYN_SENT) {
#if 1
		SQ_LOCK(&mssl->ctx->destroyq_lock);
		stream_enqueue(mssl->destroyq, cur_stream);
		SQ_UNLOCK(&mssl->ctx->destroyq_lock);
		mssl->wakeup_flag = TRUE;
#endif
		return -1;

	} else if (cur_stream->state != TCP_ST_ESTABLISHED && 
			cur_stream->state != TCP_ST_CLOSE_WAIT) {
		errno = EBADF;
		return -1;
	}
	
	SQ_LOCK(&mssl->ctx->close_lock);
	cur_stream->sndvar->on_closeq = TRUE;
	ret = stream_enqueue(mssl->closeq, cur_stream);
	mssl->wakeup_flag = TRUE;
	SQ_UNLOCK(&mssl->ctx->close_lock);

	if (ret < 0) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int 
close_listen_socket(mctx_t mctx, int sockid)
{
	mssl_manager_t mssl;
	struct tcp_listener *listener;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	listener = mssl->smap[sockid].listener;
	if (!listener) {
		errno = EINVAL;
		return -1;
	}

	if (listener->acceptq) {
		destroy_stream_queue(listener->acceptq);
		listener->acceptq = NULL;
	}

	pthread_mutex_lock(&listener->accept_lock);
	pthread_cond_signal(&listener->accept_cond);
	pthread_mutex_unlock(&listener->accept_lock);

	pthread_cond_destroy(&listener->accept_cond);
	pthread_mutex_destroy(&listener->accept_lock);

	free(listener);
	mssl->smap[sockid].listener = NULL;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mssl_close(mctx_t mctx, int sockid)
{
	mssl_manager_t mssl;
	int ret;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}


	switch (mssl->smap[sockid].socktype) {
	case MOS_SOCK_STREAM:
		ret = close_stream_socket(mctx, sockid);
		break;

	case MOS_SOCK_STREAM_LISTEN:
		ret = close_listen_socket(mctx, sockid);
		break;

	case MOS_SOCK_EPOLL:
		ret = close_epoll_socket(mctx, sockid);
		break;

	case MOS_SOCK_PIPE:
		ret = pipe_close(mctx, sockid);
		break;

	default:
		errno = EINVAL;
		ret = -1;
		break;
	}
	
	free_socket(mctx, sockid, mssl->smap[sockid].socktype);

	return ret;
}
/*----------------------------------------------------------------------------*/
int 
mssl_abort(mctx_t mctx, int sockid)
{
	mssl_manager_t mssl;
	tcp_stream *cur_stream;
	int ret;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	if (mssl->smap[sockid].socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}
	
	if (mssl->smap[sockid].socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	cur_stream = mssl->smap[sockid].stream;
	if (!cur_stream) {
		errno = ENOTCONN;
		return -1;
	}

	
	free_socket(mctx, sockid, mssl->smap[sockid].socktype);
	cur_stream->socket = NULL;

	if (cur_stream->state == TCP_ST_CLOSED_RSVD) {
		return ERROR;

	} else if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* TODO: this should notify event failure to all 
		   previous read() or write() calls */
		cur_stream->state = TCP_ST_CLOSED_RSVD;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
		SQ_LOCK(&mssl->ctx->destroyq_lock);
		stream_enqueue(mssl->destroyq, cur_stream);
		SQ_UNLOCK(&mssl->ctx->destroyq_lock);
		mssl->wakeup_flag = TRUE;
		return 0;

	} else if (cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_LAST_ACK || 
			cur_stream->state == TCP_ST_TIME_WAIT) {
		cur_stream->state = TCP_ST_CLOSED_RSVD;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		cur_stream->cb_events |= MOS_ON_TCP_STATE_CHANGE;
		SQ_LOCK(&mssl->ctx->destroyq_lock);
		stream_enqueue(mssl->destroyq, cur_stream);
		SQ_UNLOCK(&mssl->ctx->destroyq_lock);
		mssl->wakeup_flag = TRUE;
		return 0;
	}

	/* the stream structure will be destroyed after sending RST */
	if (cur_stream->sndvar->on_resetq) {
		errno = ECONNRESET;
		return -1;
	}
	SQ_LOCK(&mssl->ctx->reset_lock);
	cur_stream->sndvar->on_resetq = TRUE;
	ret = stream_enqueue(mssl->resetq, cur_stream);
	SQ_UNLOCK(&mssl->ctx->reset_lock);
	mssl->wakeup_flag = TRUE;

	if (ret < 0) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int
peek_for_user(mssl_manager_t mssl, tcp_stream *cur_stream, char *buf, int len)
{
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	int copylen;
	tcprb_t *rb = rcvvar->rcvbuf;

	if ((copylen = tcprb_ppeek(rb, (uint8_t *)buf, len, rb->pile)) <= 0) {
		errno = EAGAIN;
		return -1;
	}

	return copylen;
}
/*----------------------------------------------------------------------------*/
static inline int
copy_to_user(mssl_manager_t mssl, tcp_stream *cur_stream, char *buf, int len)
{
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	int copylen;
	tcprb_t *rb = rcvvar->rcvbuf;
	if ((copylen = tcprb_ppeek(rb, (uint8_t *)buf, len, rb->pile)) <= 0) {
		errno = EAGAIN;
		return -1;
	}
	tcprb_setpile(rb, rb->pile + copylen);

	rcvvar->rcv_wnd = rb->len - tcprb_cflen(rb);
	//printf("rcv_wnd: %d\n", rcvvar->rcv_wnd);

	/* Advertise newly freed receive buffer */
	if (cur_stream->need_wnd_adv) {
		if (rcvvar->rcv_wnd > cur_stream->sndvar->eff_mss) {
			if (!cur_stream->sndvar->on_ackq) {
				SQ_LOCK(&mssl->ctx->ackq_lock);
				cur_stream->sndvar->on_ackq = TRUE;
				stream_enqueue(mssl->ackq, cur_stream); /* this always success */
				SQ_UNLOCK(&mssl->ctx->ackq_lock);
				cur_stream->need_wnd_adv = FALSE;
				mssl->wakeup_flag = TRUE;
			}
		}
	}

	return copylen;
}
/*----------------------------------------------------------------------------*/
ssize_t
mssl_recv(mctx_t mctx, int sockid, char *buf, size_t len, int flags)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_recv_vars *rcvvar;
	int event_remaining, merged_len;
	int ret;
	
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}
	
	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}
	
	socket = &mssl->smap[sockid];
	if (socket->socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}
	
	if (socket->socktype == MOS_SOCK_PIPE) {
		return PipeRead(mctx, sockid, buf, len);
	}
	
	if (socket->socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}
	
	/* stream should be in ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
	cur_stream = socket->stream;
	if (!cur_stream || !cur_stream->rcvvar || !cur_stream->rcvvar->rcvbuf ||
	    !(cur_stream->state >= TCP_ST_ESTABLISHED && 
	      cur_stream->state <= TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}
	
	rcvvar = cur_stream->rcvvar;
	
	merged_len = tcprb_cflen(rcvvar->rcvbuf);
	
	/* if CLOSE_WAIT, return 0 if there is no payload */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		if (merged_len == 0)
			return 0;
	}
	
	/* return EAGAIN if no receive buffer */
	if (socket->opts & mssl_NONBLOCK) {
		if (merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	SBUF_LOCK(&rcvvar->read_lock);

	switch (flags) {
	case 0:
		ret = copy_to_user(mssl, cur_stream, buf, len);
		break;
	case MSG_PEEK:
		ret = peek_for_user(mssl, cur_stream, buf, len);
		break;
	default:
		SBUF_UNLOCK(&rcvvar->read_lock);
		ret = -1;
		errno = EINVAL;
		return ret;
	}
	
	merged_len = tcprb_cflen(rcvvar->rcvbuf);
	event_remaining = FALSE;
	/* if there are remaining payload, generate EPOLLIN */
	/* (may due to insufficient user buffer) */
	if (socket->epoll & MOS_EPOLLIN) {
		if (!(socket->epoll & MOS_EPOLLET) && merged_len > 0) {
			event_remaining = TRUE;
		}
	}
	/* if waiting for close, notify it if no remaining data */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
	    merged_len == 0 && ret > 0) {
		event_remaining = TRUE;
	}
	
	SBUF_UNLOCK(&rcvvar->read_lock);
	
	if (event_remaining) {
		if (socket->epoll) {
			add_epoll_event(mssl->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLIN);
		}
	}
	
	return ret;
}
/*----------------------------------------------------------------------------*/
inline ssize_t
mssl_read(mctx_t mctx, int sockid, char *buf, size_t len)
{
	return mssl_recv(mctx, sockid, buf, len, 0);
}
/*----------------------------------------------------------------------------*/
ssize_t
mssl_readv(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_recv_vars *rcvvar;
	int ret, bytes_read, i;
	int event_remaining, merged_len;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	socket = &mssl->smap[sockid];
	if (socket->socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}
	
	if (socket->socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	/* stream should be in ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
	cur_stream = socket->stream;
	if (!cur_stream || !cur_stream->rcvvar->rcvbuf ||
			!(cur_stream->state >= TCP_ST_ESTABLISHED && 
			  cur_stream->state <= TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	rcvvar = cur_stream->rcvvar;

	merged_len = tcprb_cflen(rcvvar->rcvbuf);

	/* if CLOSE_WAIT, return 0 if there is no payload */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		if (merged_len == 0)
			return 0;
	}

	/* return EAGAIN if no receive buffer */
	if (socket->opts & mssl_NONBLOCK) {
		if (merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	SBUF_LOCK(&rcvvar->read_lock);
	
	/* read and store the contents to the vectored buffers */ 
	bytes_read = 0;
	for (i = 0; i < numIOV; i++) {
		if (iov[i].iov_len <= 0)
			continue;

		ret = copy_to_user(mssl, cur_stream, iov[i].iov_base, iov[i].iov_len);
		if (ret <= 0)
			break;

		bytes_read += ret;

		if (ret < iov[i].iov_len)
			break;
	}

	merged_len = tcprb_cflen(rcvvar->rcvbuf);

	event_remaining = FALSE;
	/* if there are remaining payload, generate read event */
	/* (may due to insufficient user buffer) */
	if (socket->epoll & MOS_EPOLLIN) {
		if (!(socket->epoll & MOS_EPOLLET) && merged_len > 0) {
			event_remaining = TRUE;
		}
	}
	/* if waiting for close, notify it if no remaining data */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
			merged_len == 0 && bytes_read > 0) {
		event_remaining = TRUE;
	}

	SBUF_UNLOCK(&rcvvar->read_lock);

	if(event_remaining) {
		if (socket->epoll & MOS_EPOLLIN && !(socket->epoll & MOS_EPOLLET)) {
			add_epoll_event(mssl->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLIN);
		}
	}

	return bytes_read;
}
/*----------------------------------------------------------------------------*/
static inline int 
copy_from_user(mssl_manager_t mssl, tcp_stream *cur_stream, const char *buf, int len)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int sndlen;
	int ret;

	sndlen = MIN((int)sndvar->snd_wnd, len);
	if (sndlen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	/* allocate send buffer if not exist */
	if (!sndvar->sndbuf) {
		sndvar->sndbuf = sb_init(mssl->rbm_snd, sndvar->iss + 1);
		if (!sndvar->sndbuf) {
			cur_stream->close_reason = TCP_NO_MEM;
			/* notification may not required due to -1 return */
			errno = ENOMEM;
			return -1;
		}
	}

	ret = sb_put(mssl->rbm_snd, sndvar->sndbuf, buf, sndlen);
	assert(ret == sndlen);
	sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;
	if (ret <= 0) {
		errno = EAGAIN;
		return -1;
	}
	
	if (sndvar->snd_wnd <= 0) {
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
ssize_t
mssl_write(mctx_t mctx, int sockid, const char *buf, size_t len)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_send_vars *sndvar;
	int ret;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	socket = &mssl->smap[sockid];
	if (socket->socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (socket->socktype == MOS_SOCK_PIPE) {
		return pipe_write(mctx, sockid, buf, len);
	}

	if (socket->socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}
	
	cur_stream = socket->stream;
	if (!cur_stream || 
			!(cur_stream->state == TCP_ST_ESTABLISHED || 
			  cur_stream->state == TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	if (len <= 0) {
		if (socket->opts & mssl_NONBLOCK) {
			errno = EAGAIN;
			return -1;
		} else {
			return 0;
		}
	}

	sndvar = cur_stream->sndvar;

	SBUF_LOCK(&sndvar->write_lock);
	ret = copy_from_user(mssl, cur_stream, buf, len);

	SBUF_UNLOCK(&sndvar->write_lock);

	if (ret > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		SQ_LOCK(&mssl->ctx->sendq_lock);
		sndvar->on_sendq = TRUE;
		stream_enqueue(mssl->sendq, cur_stream);		/* this always success */
		SQ_UNLOCK(&mssl->ctx->sendq_lock);
		mssl->wakeup_flag = TRUE;
	}

	if (ret == 0 && (socket->opts & mssl_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

	/* if there are remaining sending buffer, generate write event */
	if (sndvar->snd_wnd > 0) {
		if (socket->epoll & MOS_EPOLLOUT && !(socket->epoll & MOS_EPOLLET)) {
			add_epoll_event(mssl->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLOUT);
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
ssize_t
mssl_writev(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV)
{
	mssl_manager_t mssl;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_send_vars *sndvar;
	int ret, to_write, i;

	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}

	if (sockid < 0 || sockid >= g_config.mos->max_concurrency) {
		errno = EBADF;
		return -1;
	}

	socket = &mssl->smap[sockid];
	if (socket->socktype == MOS_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (socket->socktype != MOS_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}
	
	cur_stream = socket->stream;
	if (!cur_stream || 
			!(cur_stream->state == TCP_ST_ESTABLISHED || 
			  cur_stream->state == TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	sndvar = cur_stream->sndvar;
	SBUF_LOCK(&sndvar->write_lock);

	/* write from the vectored buffers */ 
	to_write = 0;
	for (i = 0; i < numIOV; i++) {
		if (iov[i].iov_len <= 0)
			continue;

		ret = copy_from_user(mssl, cur_stream, iov[i].iov_base, iov[i].iov_len);
		if (ret <= 0)
			break;

		to_write += ret;

		if (ret < iov[i].iov_len)
			break;
	}
	SBUF_UNLOCK(&sndvar->write_lock);

	if (to_write > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		SQ_LOCK(&mssl->ctx->sendq_lock);
		sndvar->on_sendq = TRUE;
		stream_enqueue(mssl->sendq, cur_stream);		/* this always success */
		SQ_UNLOCK(&mssl->ctx->sendq_lock);
		mssl->wakeup_flag = TRUE;
	}

	if (to_write == 0 && (socket->opts & mssl_NONBLOCK)) {
		to_write = -1;
		errno = EAGAIN;
	}

	/* if there are remaining sending buffer, generate write event */
	if (sndvar->snd_wnd > 0) {
		if (socket->epoll & MOS_EPOLLOUT && !(socket->epoll & MOS_EPOLLET)) {
			add_epoll_event(mssl->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MOS_EPOLLOUT);
		}
	}

	return to_write;
}
/*----------------------------------------------------------------------------*/
uint32_t
mssl_get_connection_cnt(mctx_t mctx)
{
	mssl_manager_t mssl;
	mssl = get_mssl_manager(mctx);
	if (!mssl) {
		errno = EACCES;
		return -1;
	}
	
	if (mssl->num_msp > 0)
		return mssl->flow_cnt / 2;
	else
		return mssl->flow_cnt;
}
/*----------------------------------------------------------------------------*/
