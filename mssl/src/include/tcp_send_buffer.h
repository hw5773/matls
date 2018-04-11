#ifndef __TCP_SEND_BUFFER_H__
#define __TCP_SEND_BUFFER_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct sb_manager *sb_manager_t;

struct tcp_send_buffer
{
  unsigned char *data;
  unsigned char *head;

  uint32_t head_off;
  uint32_t tail_off;
  uint32_t len;
  uint64_t cum_len;
  uint32_t size;

  uint32_t head_seq;
  uint32_t init_seq;
};

uint32_t sb_get_curnum(sb_manager_t sbm);
sb_manager_t sb_manager_create(size_t chunk_size, uint8_t disable_rings, uint32_t concurrency);
struct tcp_send_buffer *sb_init(sb_manager_t sbm, uint32_t init_seq);
void sb_free(sb_manager_t sbm, struct tcp_send_buffer *buf);
size_t sb_put(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len);
size_t sb_remove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len);

#endif /* __TCP_SEND_BUFFER_H__ */
