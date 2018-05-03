#include "include/logs.h"
#include <string.h>

#include "include/config.h"
#include "include/tcp_stream.h"
#include "include/fhash.h"
#include "include/tcp.h"
#include "include/tcp_in.h"
#include "include/tcp_out.h"
#include "include/tcp_ring_buffer.h"
//#include "include/tcp_send_buffer.h"
#include "include/eventpoll.h"
#include "include/ip_out.h"
//#include "include/timer.h"
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

static int posix_seq_rand(void)
{
  next = next * 1103515245 + 12345;
  return ((unsigned)(next/66536) % 32768);
}

void posix_seq_srand(unsigned seed)
{
  next = seed % 32768;
}

// int get_frag_info
