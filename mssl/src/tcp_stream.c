#include "include/logs.h"
#include <string.h>

#include "include/config.h"
#include "include/tcp_stream.h"
#include "include/fhash.h"
#include "include/tcp.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/tcp_ring_buffer.h"
#include "include/tcp_send_buffer.h"
#include "include/eventpoll.h"
#include "include/ip_out.h"
#include "include/timer.h"
#include "include/tcp_rb.h"

char *state_str[] =
{
  "TCP_ST_CLOSED",
  "TCP_ST_LISTEN",
  "TCP_ST_SYN_SENT",
  "TCP_ST_SYN_RCVD",
  "TCP_ST_ESTABLISHED",
  "TCP_ST_FIN_WAIT_1",
  "TCP_ST_FIN_WAIT_2",
  "TCP_ST_CLOSE_WAIT",
  "TCP_ST_CLOSING",
  "TCP_ST_LAST_ACK",
  "TCP_ST_TIME_WAIT",
  "TCP_ST_CLOSED_RSVD"
};

char *close_reason_str[] =
{
  "NOT_CLOSED",
  "CLOSE",
  "CLOSED",
  "CONN_FAIL",
  "CONN_LOST",
  "RESET",
  "NO_MEM",
  "DENIED",
  "TIMEDOUT"
};

static __thread unsigned long next = 1;

int posix_seq_rand(void)
{
  next = next * 1103515245 + 12345;
  return ((unsigned)(next/66536) % 32768);
}

void posix_seq_srand(unsigned seed)
{
  next = seed % 32768;
}

int get_frag_info(socket_map_t sock, int side, void *optval, socklen_t *len) 
{
	struct tcp_stream *stream;

	stream = NULL;
	if (!*len || ( *len % sizeof(tcpfrag_t) != 0))
		goto frag_info_error;

	if (side != MOS_SIDE_CLI && side != MOS_SIDE_SVR) {
		exit(EXIT_FAILURE);
		return -1;
	}

	struct tcp_stream *mstrm = sock->monitor_stream->stream;
	stream = (side == mstrm->side) ? mstrm : mstrm->pair_stream;

	if (stream == NULL) goto frag_info_error;
	
	/* First check if the tcp ring buffer even has anything */
	if (stream->rcvvar != NULL &&
	    stream->rcvvar->rcvbuf != NULL) {
		tcprb_t *rcvbuf = stream->rcvvar->rcvbuf;
		struct tcp_ring_fragment *out = (struct tcp_ring_fragment *)optval;
		int const maxout = *len;
		*len = 0;
		struct _tcpfrag_t *walk;
		TAILQ_FOREACH(walk, &rcvbuf->frags, link) {
			if (*len == maxout)
				break;
			out[*len].offset = walk->head;
			out[*len].len = walk->tail - walk->head;
			(*len)++;
		}
		if (*len != maxout) {
			/* set zero sentinel */
			out[*len].offset = 0;
			out[*len].len = 0;
		}
	} else
		goto frag_info_error;

	return 0;

 frag_info_error:
	optval = NULL;
	*len = 0;
	return -1;
}

int get_buf_info(socket_map_t sock, int side, void *optval, socklen_t *len)
{
	struct tcp_stream *stream;
	struct tcp_buf_info *tbi;
	
	tbi = (struct tcp_buf_info *)optval;
	memset(tbi, 0, sizeof(struct tcp_buf_info));
	stream = NULL;

	if (*len != sizeof(struct tcp_buf_info)) {
		errno = EINVAL;
		goto buf_info_error;
	}

	if (side != MOS_SIDE_CLI && side != MOS_SIDE_SVR) {
		errno = EINVAL;
		goto buf_info_error;
	}

	struct tcp_stream *mstrm = sock->monitor_stream->stream;
	stream = (side == mstrm->side) ? mstrm : mstrm->pair_stream;

	/* First check if the tcp ring buffer even has anything */
	if (stream != NULL &&
	    stream->rcvvar != NULL &&
	    stream->rcvvar->rcvbuf != NULL) {
		tcprb_t *rcvbuf = stream->rcvvar->rcvbuf;
		tcpfrag_t *f = TAILQ_LAST(&rcvbuf->frags, flist);
		tbi->tcpbi_init_seq = stream->rcvvar->irs + 1;
		tbi->tcpbi_last_byte_read = rcvbuf->pile;
		tbi->tcpbi_next_byte_expected = rcvbuf->pile + tcprb_cflen(rcvbuf);
		tbi->tcpbi_last_byte_received = (f ? f->tail : rcvbuf->head);
	} else {
		errno = ENODATA;
		goto buf_info_error;
	}
	
	return 0;

 buf_info_error:
	optval = NULL;
	*len = 0;
	return -1;
}

int disable_buf(socket_map_t sock, int side)
{
#ifdef DBGMSG
	__PREPARE_DBGLOGGING();
#endif
	struct tcp_stream *stream;
	int rc = 0;

	switch (sock->socktype) {
	case MOS_SOCK_MONITOR_STREAM:
		if (side == MOS_SIDE_CLI)
			sock->monitor_listener->client_buf_mgmt = 0;
		else if (side == MOS_SIDE_SVR)
			sock->monitor_listener->server_buf_mgmt = 0;
		else {
			assert(0);
			rc = -1;
		}
		break;
	case MOS_SOCK_MONITOR_STREAM_ACTIVE:
		stream = sock->monitor_stream->stream;
		if (stream->side != side)
			stream = stream->pair_stream;
		assert(stream->side == side);
		stream->buffer_mgmt = 0;
		break;
	default:
		assert(0);
		rc = -1;
	}
	
	return rc;
}

int get_last_timestamp(struct tcp_stream *stream, uint32_t *usecs, socklen_t *len)
{
#ifdef DBGMSG
	__PREPARE_DBGLOGGING();
#endif
	if (*len < sizeof(uint32_t)) {
		return -1;
	}
	
	*usecs = (stream->last_active_ts >
		  stream->pair_stream->last_active_ts) 
		?
		TS_TO_USEC(stream->last_active_ts) : 
		TS_TO_USEC(stream->pair_stream->last_active_ts);
	
	return 0;
}

inline int get_tcp_state(struct tcp_stream *stream, int side,
			void *optval, socklen_t *optlen)
{
	if (!stream || !(stream = (side == stream->side) ? stream : stream->pair_stream))
		return -1;
	*(int *)optval = (int)((stream->state == TCP_ST_CLOSED_RSVD) ?
						   TCP_ST_CLOSED : stream->state);
	return 0;
}

inline char *tcp_state_to_string(const tcp_stream *stream)
{
	return (stream) ? state_str[stream->state] : NULL;
}

inline void raise_read_event(mssl_manager_t mssl, tcp_stream *stream)
{
  struct tcp_recv_vars *rcvvar;
  rcvvar = stream->rcvvar;

  if (HAS_STREAM_TYPE(stream, MOS_SOCK_STREAM))
  {
    MA_LOG("read event with MOS_SOCK_STREAM");
    if (stream->socket && (stream->socket->epoll & MOS_EPOLLIN))
      add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, stream->socket, MOS_EPOLLIN);
  }
  else if (rcvvar->rcvbuf && tcprb_cflen(rcvvar->rcvbuf) > 0)
  {
    MA_LOG("read event with MOS_SOCK_MONITOR_STREAM_ACTIVE");
    int index;
    struct event_queue *eq;
    struct socket_map *walk;

    SOCKQ_FOREACH_START(walk, &stream->msocks)
    {
      assert(walk->socktype == MOS_SOCK_MONITOR_STREAM_ACTIVE);
      eq = walk->monitor_stream->monitor_listener->eq;

      if (stream->actions & MOS_ACT_READ_DATA)
        return;
      if (eq->num_events >= eq->size)
      {
        return;
      }

      index = eq->end++;
      eq->events[index].ev.events = MOS_EPOLLIN;
      eq->events[index].ev.data.ptr = (void *)stream;

      if (eq->end >= eq->size)
      {
        eq->end = 0;
      }
      eq->num_events++;
      stream->actions |= MOS_ACT_READ_DATA;
    } SOCKQ_FOREACH_END;
  }
  else
  {
    MA_LOG("raising read without a socket");
  }
  // MOS_SOCK_MONITOR_STREAM_ACTIVE
}

inline void raise_write_event(mssl_manager_t mssl, tcp_stream *stream)
{
  if (stream->socket)
  {
    if (stream->socket->epoll & MOS_EPOLLOUT)
    {
      add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, stream->socket, MOS_EPOLLOUT);
    }
  }
}

inline void raise_close_event(mssl_manager_t mssl, tcp_stream *stream)
{
  if (stream->socket)
  {
    if (stream->socket->epoll & MOS_EPOLLRDHUP)
    {
      add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, stream->socket, MOS_EPOLLRDHUP);
    }
    else if (stream->socket->epoll & MOS_EPOLLIN)
    {
      add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, stream->socket, MOS_EPOLLIN);
    }
  }
}

inline int raise_error_event(mssl_manager_t mssl, tcp_stream *stream)
{
  if (stream->socket)
  {
    if (stream->socket->epoll & MOS_EPOLLERR)
    {
      return add_epoll_event(mssl->ep, MOS_EVENT_QUEUE, stream->socket, MOS_EPOLLERR);
    }
  }
  return -1;
}

int add_monitor_stream_sockets(mssl_manager_t mssl, struct tcp_stream *stream)
{
  struct mssl_context mctx;
  int socktype;

  mctx.cpu = mssl->ctx->cpu;
  struct mon_listener *walk;

  TAILQ_FOREACH(walk, &mssl->monitors, link)
  {
    socktype = walk->socket->socktype;

    if (socktype != MOS_SOCK_SPLIT_TLS)
      continue;

    if (!walk->is_stream_syn_filter_hit)
      continue;

    struct socket_map *s = allocate_socket(&mctx, MOS_SOCK_SPLIT_TLS); 
    if (!s)
      return -1;

    s->monitor_stream->socket = s;
    s->monitor_stream->stream = stream;
    s->monitor_stream->monitor_listener = walk;
    s->monitor_stream->client_buf_mgmt = walk->client_buf_mgmt;
    s->monitor_stream->server_buf_mgmt = walk->server_buf_mgmt;
    s->monitor_stream->client_mon = walk->client_mon;
    s->monitor_stream->server_mon = walk->server_mon;

    /* events */

    SOCKQ_INSERT_TAIL(&stream->msocks, s);
  }

  return 0;
}


// int destroy_monitor_stream_socket

tcp_stream *create_tcp_stream(mssl_manager_t mssl, socket_map_t socket, int type,
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, unsigned int *hash)
{
  tcp_stream *stream = NULL;
  int ret;
  bool flow_lock = type & STREAM_TYPE(MOS_SOCK_STREAM);

  if (flow_lock)
    pthread_mutex_lock(&mssl->ctx->flow_pool_lock);

  stream = (tcp_stream *)mp_allocate_chunk(mssl->flow_pool);
  if (!stream)
  {
    MA_LOG("Cannot allocate memory for the stream");
    if (flow_lock)
      pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);
    return NULL;
  }
  memset(stream, 0, sizeof(tcp_stream));

  stream->rcvvar = (struct tcp_recv_vars *)mp_allocate_chunk(mssl->rv_pool);
  if (!stream->rcvvar)
  {
    mp_free_chunk(mssl->flow_pool, stream);
    if (flow_lock)
      pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);
    return NULL;
  }
  memset(stream->rcvvar, 0, sizeof(struct tcp_recv_vars));

  stream->sndvar = (struct tcp_send_vars *)mp_allocate_chunk(mssl->sv_pool);
  if (!stream->sndvar)
  {
    mp_free_chunk(mssl->rv_pool, stream->rcvvar);
    mp_free_chunk(mssl->flow_pool, stream);
    if (flow_lock)
      pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);
    return NULL;
  }
  memset(stream->sndvar, 0, sizeof(struct tcp_send_vars));

  stream->id = mssl->g_id++;
  stream->saddr = saddr;
  stream->sport = sport;
  stream->daddr = daddr;
  stream->dport = dport;

  ret = HTInsert(mssl->tcp_flow_table, stream, hash);
  if (ret < 0)
  {
    MA_LOG("Failed to insert the stream into hash table");
    mp_free_chunk(mssl->flow_pool, stream);
    if (flow_lock)
      pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);
    return NULL;
  }
  stream->on_hash_table = TRUE;
  mssl->flow_cnt++;

  SOCKQ_INIT(&stream->msocks);
/*
  if ((mssl->num_msp > 0) &&
      (type & STREAM_TYPE(MOS_SOCK_SPLIT_TLS)))
    if (add_monitor_stream_sockets(mssl, stream) < 0)
      MA_LOG("Could not create monitor stream socket!");
*/
  if (flow_lock)
    pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);

  if (socket)
  {
    stream->socket = socket;
    socket->stream = stream;
  }

  stream->stream_type = type;
  stream->state = TCP_ST_LISTEN;
  stream->on_rto_idx = -1;
  
  stream->sndvar->mss = TCP_DEFAULT_MSS;
  stream->sndvar->wscale_mine = TCP_DEFAULT_WSCALE;
  stream->sndvar->wscale_peer = 0;

//  if (HAS_STREAM_TYPE(stream, MOS_SOCK_SPLIT_TLS))
//  {
  stream->sndvar->ip_id = 0;
  stream->sndvar->nif_out = get_output_interface(stream->daddr);

  stream->sndvar->iss = posix_seq_rand() % TCP_MAX_SEQ;
  stream->snd_nxt = stream->sndvar->iss;
  stream->sndvar->snd_una = stream->sndvar->iss;
  stream->sndvar->snd_wnd = g_config.mos->wmem_size;
  stream->sndvar->rto = TCP_INITIAL_RTO;
#if USE_SPIN_LOCK
  if (pthread_spin_init(&stream->sndvar->write_lock, PTHREAD_PROCESS_PRIVATE))
  {
#else
  if (pthread_mutex_init(&stream->sndvar->write_lock, NULL))
  {
#endif
    perror("pthread_mutex_init of write_lock");
    pthread_mutex_destroy(&stream->rcvvar->read_lock);

    return NULL;
  }
//  }
  stream->rcvvar->irs = 0;
  stream->rcv_nxt = 0;
  stream->rcvvar->rcv_wnd = TCP_INITIAL_WINDOW;
  stream->rcvvar->snd_wl1 = stream->rcvvar->irs - 1;
  stream->buffer_mgmt = BUFMGMT_FULL;
  stream->status_mgmt = 1;

#if USE_SPIN_LOCK
  if (pthread_spin_init(&stream->rcvvar->read_lock, PTHREAD_PROCESS_PRIVATE))
  {
#else
  if (pthread_mutex_init(&stream->rcvvar->read_lock, NULL))
  {
#endif
    perror("pthread_mutex_init of read lock");
    return NULL;
  }

  MA_LOG("Create new TCP stream");
  MA_LOGip("  Source IP", stream->saddr);
  MA_LOG1d("  Source Port", ntohs(stream->sport));
  MA_LOGip("  Destination IP", stream->daddr);
  MA_LOG1d("  Destination Port", ntohs(stream->dport));
  MA_LOG1p("Stream Pointer", stream);

  return stream;
}

inline tcp_stream *create_dual_tcp_stream(mssl_manager_t mssl, socket_map_t socket, int type, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, unsigned int *hash)
{
  MA_LOG("create dual tcp stream");
  tcp_stream *cur_stream, *paired_stream;
  struct socket_map *walk;

  cur_stream = create_tcp_stream(mssl, socket, type, daddr, dport, saddr, sport, hash);
  if (!cur_stream)
  {
    MA_LOG("Cannot create tcp_stream");
    return NULL;
  }

  paired_stream = create_tcp_stream(mssl, NULL, MOS_SOCK_UNUSED, saddr, sport, daddr, dport, hash);
  if (!paired_stream)
  {
    destroy_tcp_stream(mssl, cur_stream);
    return NULL;
  }

  cur_stream->pair_stream = paired_stream;
  paired_stream->pair_stream = cur_stream;
  paired_stream->socket = socket;
  SOCKQ_FOREACH_START(walk, &cur_stream->msocks)
  {
    SOCKQ_INSERT_TAIL(&paired_stream->msocks, walk);
  }
  SOCKQ_FOREACH_END;
  paired_stream->stream_type = STREAM_TYPE(MOS_SOCK_SPLIT_TLS);

  MA_LOG1s("cur_stream state", state_str[cur_stream->state]);
  MA_LOG1s("paired_stream state", state_str[paired_stream->state]);

  return cur_stream;
}

inline tcp_stream *create_client_tcp_stream(mssl_manager_t mssl, socket_map_t socket, int type,
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, unsigned int *hash)
{
  MA_LOG("create client tcp stream");
  tcp_stream *cs;
  struct socket_map *w;

  ///// Add for matls /////
  //socket = allocate_socket(mssl->ctx, MOS_SOCK_SPLIT_TLS);
  /////////////////////////
  cs = create_tcp_stream(mssl, socket, type, daddr, dport, saddr, sport, hash);
  if (!cs)
  {
    MA_LOG("Cannot create tcp_stream");
    return NULL;
  }

  cs->side = MOS_SIDE_CLI;
  cs->pair_stream = NULL;

  /*
   * Something related to the buffer management
   */

  return cs;
}

inline tcp_stream *attach_server_tcp_stream(mssl_manager_t mssl, 
    tcp_stream *cs, int type, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
  MA_LOG("attach server tcp stream");
  tcp_stream *ss;
  struct socket_map *w;

  ss = create_tcp_stream(mssl, NULL, MOS_SOCK_SPLIT_TLS, saddr, sport, daddr, dport, NULL);

  if (ss == NULL)
  {
    MA_LOG("Can't create tcp_stream");
    return NULL;
  }

  ss->side = MOS_SIDE_SVR;
  ss->socket = NULL;
  ss->pair_stream = cs;
  cs->pair_stream = ss;
  ss->stream_type = STREAM_TYPE(MOS_SOCK_SPLIT_TLS);
}

static void destroy_single_tcp_stream(mssl_manager_t mssl, tcp_stream *stream)
{
  struct sockaddr_in addr;
  int bound_addr = FALSE;
  int ret, hash = 0;
  bool flow_lock = HAS_STREAM_TYPE(stream, MOS_SOCK_STREAM);

  struct socket_map *walk;

  stream->state = TCP_ST_CLOSED_RSVD;

/*
  SOCKQ_FOREACH_START(walk, &stream->msocks)
  
*/

  /* remove from lists */

  if (flow_lock)
    pthread_mutex_lock(&mssl->ctx->flow_pool_lock);

  if (HTSearch(mssl->tcp_flow_table, stream, stream, &hash))
  {
    HTRemove(mssl->tcp_flow_table, stream);
    stream->on_hash_table = FALSE;

    mssl->flow_cnt--;

    mp_free_chunk(mssl->rv_pool, stream->rcvvar);
    mp_free_chunk(mssl->sv_pool, stream->sndvar);
    mp_free_chunk(mssl->flow_pool, stream);
  }

  if (flow_lock)
    pthread_mutex_unlock(&mssl->ctx->flow_pool_lock);

  /* bound addr */
}

void destroy_tcp_stream(mssl_manager_t mssl, tcp_stream *stream)
{
  tcp_stream *pair_stream = stream->pair_stream;

  destroy_single_tcp_stream(mssl, stream);

  if (pair_stream)
    destroy_single_tcp_stream(mssl, pair_stream);
}
