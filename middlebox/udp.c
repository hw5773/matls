#include "udp.h"
#include "mb_log.h"

int process_udp(uint8_t *buf, int len)
{
  return _process_udp(buf, len);
}

int _process_udp(uint8_t *buf, int len)
{
  struct udphdr *udph = (struct udphdr *)buf;
  MB_LOG1d("Source Port", udph->source);
  MB_LOG1d("Destination Port", udph->dest);

  return 1;
}
