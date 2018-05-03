#include "mb_log.h"
#include "tcp.h"

int process_tcp(uint8_t *buf, int len)
{
  return _process_tcp(buf, len);
}

int _process_tcp(uint8_t *buf, int len)
{
  struct tcphdr *tcph = (struct tcphdr *)buf;
  MB_LOG1d("Source Port", ntohs(tcph->source));
  MB_LOG1d("Destination Port", ntohs(tcph->dest));

  return 1;
}
